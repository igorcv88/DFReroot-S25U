import com.polygraphene.df.reroot.AutoRootPolicy;
import com.polygraphene.df.reroot.SoftRebootHealthPolicy;
import com.polygraphene.df.reroot.SoftRebootHealthPolicy.Observation;
import com.polygraphene.df.reroot.SoftRebootHealthPolicy.Snapshot;

/**
 * Host tests for the OEM boot-health policy.
 *
 * Every element of the verdict gets its negative case, because a gate that
 * cannot fail is not a gate (AGENTS.md section 5). None of these states can be
 * produced on demand on a device: `dev.platform_bootcomplete` is zeroed by the
 * firmware's own init trigger during a zygote restart, `bootchecker` is a
 * oneshot that is `running` only while the watchdog is waiting,
 * `crashrecovery.attempting_reboot` is set moments before the device reboots,
 * and the record's two halves are written by two different processes - the
 * second exists only because the first was killed.
 */
public class SoftRebootHealthPolicyTest {

    static final String BOOT = "68845faf-d5b9-4622-a5d9-c5e7885e1bc1";
    static final String OTHER_BOOT = "85e3a031-42bb-49cc-8bbe-c276cb4b5c4e";

    static int pass = 0;
    static int fail = 0;

    /** The healthy ZZIC full boot, exactly as the device reported it. */
    static Snapshot healthy() {
        Snapshot s = new Snapshot();
        s.put(SoftRebootHealthPolicy.PROP_SYS_BOOT_COMPLETED, "1");
        s.put(SoftRebootHealthPolicy.PROP_DEV_BOOTCOMPLETE, "1");
        s.put(SoftRebootHealthPolicy.PROP_DEV_PLATFORM_BOOTCOMPLETE, "1");
        s.put(SoftRebootHealthPolicy.PROP_INIT_SVC_ZYGOTE, "running");
        s.put(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER, "stopped");
        s.put(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER_BOOTC, "stopped");
        // Unset on a healthy boot, which is a reading, not a failure.
        s.put(SoftRebootHealthPolicy.PROP_CRASHRECOVERY_ATTEMPTING_REBOOT, "");
        s.put(SoftRebootHealthPolicy.PROP_UPDATABLE_CRASHING, null);
        s.put(SoftRebootHealthPolicy.PROP_UPDATABLE_CRASHING_PROCESS_NAME, "");
        s.put(SoftRebootHealthPolicy.PROP_DEV_ATTEMPTING_REBOOT, "");
        s.readStartMs = 41_000L;
        s.readEndMs = 41_004L;
        s.pid = 3028L;
        s.procStarttime = 9_100L;
        return s;
    }

    /**
     * A device that runs no OEM boot watchdog: the three OEM-only properties are
     * unset while AOSP's own flag says the boot completed.
     */
    static Snapshot generic() {
        Snapshot s = healthy();
        s.put(SoftRebootHealthPolicy.PROP_DEV_PLATFORM_BOOTCOMPLETE, "");
        s.put(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER, "");
        s.put(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER_BOOTC, "");
        s.pid = 1234L;
        s.procStarttime = 500L;
        return s;
    }

    static Snapshot with(String property, String value) {
        Snapshot s = healthy();
        s.put(property, value);
        return s;
    }

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            pass++;
            System.out.println("  ok   - " + name + (detail == null ? "" : " (" + detail + ")"));
        } else {
            fail++;
            System.out.println("  FAIL - " + name + ": " + detail);
        }
    }

    static void verdictIs(String name, Snapshot s, String expected) {
        String actual = SoftRebootHealthPolicy.verdict(s);
        check(name, expected.equals(actual), actual);
    }

    static void malformed(String name, String record) {
        Observation o = SoftRebootHealthPolicy.observe(record, BOOT);
        check(name, SoftRebootHealthPolicy.OBS_MALFORMED.equals(o.state), o.state);
    }

    static String pre() {
        return SoftRebootHealthPolicy.formatPreExec(BOOT, healthy());
    }

    public static void main(String[] args) {
        System.out.println("[T] SoftRebootHealthPolicy");

        // --- the one positive -----------------------------------------------
        verdictIs("healthy ZZIC full boot converges", healthy(),
                SoftRebootHealthPolicy.CONVERGED);

        // --- scope: a device with no OEM watchdog is not a candidate ---------
        verdictIs("a device with no OEM boot watchdog is not a candidate", generic(),
                SoftRebootHealthPolicy.NOT_APPLICABLE);
        for (String oem : new String[] {
                SoftRebootHealthPolicy.PROP_DEV_PLATFORM_BOOTCOMPLETE,
                SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER,
                SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER_BOOTC }) {
            Snapshot partial = generic();
            partial.put(oem, oem.startsWith("init.svc") ? "running" : "0");
            check("a partially present OEM mechanism is never NOT_APPLICABLE (" + oem + ")",
                    SoftRebootHealthPolicy.PENDING.equals(
                            SoftRebootHealthPolicy.verdict(partial)),
                    SoftRebootHealthPolicy.verdict(partial));
        }
        Snapshot genericBooting = generic();
        genericBooting.put(SoftRebootHealthPolicy.PROP_SYS_BOOT_COMPLETED, "0");
        verdictIs("an incomplete boot is never NOT_APPLICABLE", genericBooting,
                SoftRebootHealthPolicy.PENDING);
        Snapshot genericUnreadable = generic();
        genericUnreadable.put(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER,
                SoftRebootHealthPolicy.UNKNOWN);
        verdictIs("an unreadable OEM property is UNKNOWN, never NOT_APPLICABLE",
                genericUnreadable, SoftRebootHealthPolicy.HEALTH_UNKNOWN);
        Snapshot genericCrashing = generic();
        genericCrashing.put(SoftRebootHealthPolicy.PROP_CRASHRECOVERY_ATTEMPTING_REBOOT, "true");
        verdictIs("CrashRecovery outranks applicability; it is AOSP's, not the OEM's",
                genericCrashing, SoftRebootHealthPolicy.CRASH_RECOVERY);

        // --- the three boot-completion flags, one at a time ------------------
        verdictIs("sys.boot_completed not yet 1",
                with(SoftRebootHealthPolicy.PROP_SYS_BOOT_COMPLETED, "0"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("dev.bootcomplete not yet 1",
                with(SoftRebootHealthPolicy.PROP_DEV_BOOTCOMPLETE, "0"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("dev.platform_bootcomplete zeroed by the zygote-restart trigger",
                with(SoftRebootHealthPolicy.PROP_DEV_PLATFORM_BOOTCOMPLETE, "0"),
                SoftRebootHealthPolicy.PENDING);

        // --- the services that own the OEM half ------------------------------
        verdictIs("zygote restarting is never a converged boot",
                with(SoftRebootHealthPolicy.PROP_INIT_SVC_ZYGOTE, "restarting"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("bootchecker still running means the watchdog is waiting",
                with(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER, "running"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("bootchecker-bootc still running",
                with(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER_BOOTC, "running"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("an init service state this build cannot account for",
                with(SoftRebootHealthPolicy.PROP_INIT_SVC_ZYGOTE, "zombie"),
                SoftRebootHealthPolicy.HEALTH_UNKNOWN);

        // --- CrashRecovery, kept apart from "pending" ------------------------
        verdictIs("CrashRecovery is attempting a reboot",
                with(SoftRebootHealthPolicy.PROP_CRASHRECOVERY_ATTEMPTING_REBOOT, "true"),
                SoftRebootHealthPolicy.CRASH_RECOVERY);
        verdictIs("an updatable process is crashing",
                with(SoftRebootHealthPolicy.PROP_UPDATABLE_CRASHING, "1"),
                SoftRebootHealthPolicy.CRASH_RECOVERY);
        verdictIs("updatable_crashing explicitly 0 is not a crash",
                with(SoftRebootHealthPolicy.PROP_UPDATABLE_CRASHING, "0"),
                SoftRebootHealthPolicy.CONVERGED);
        verdictIs("attempting_reboot explicitly false is not a crash",
                with(SoftRebootHealthPolicy.PROP_CRASHRECOVERY_ATTEMPTING_REBOOT, "false"),
                SoftRebootHealthPolicy.CONVERGED);
        verdictIs("a tri-state property with a fourth value refuses",
                with(SoftRebootHealthPolicy.PROP_CRASHRECOVERY_ATTEMPTING_REBOOT, "maybe"),
                SoftRebootHealthPolicy.HEALTH_UNKNOWN);
        Snapshot unreadableCrash = healthy();
        unreadableCrash.put(SoftRebootHealthPolicy.PROP_SYS_BOOT_COMPLETED, "0");
        unreadableCrash.put(SoftRebootHealthPolicy.PROP_UPDATABLE_CRASHING,
                SoftRebootHealthPolicy.UNKNOWN);
        verdictIs("an unreadable crash signal outranks a pending flag",
                unreadableCrash, SoftRebootHealthPolicy.HEALTH_UNKNOWN);

        // --- telemetry is recorded and never gates ---------------------------
        for (String t : SoftRebootHealthPolicy.TELEMETRY) {
            verdictIs("an unreadable telemetry field refuses nothing (" + t + ")",
                    with(t, SoftRebootHealthPolicy.UNKNOWN),
                    SoftRebootHealthPolicy.CONVERGED);
            verdictIs("a populated telemetry field decides nothing either (" + t + ")",
                    with(t, "bootchecker_timeout"), SoftRebootHealthPolicy.CONVERGED);
        }
        check("the telemetry fields are not part of the gating set",
                !SoftRebootHealthPolicy.PROPERTIES.contains(
                        SoftRebootHealthPolicy.PROP_UPDATABLE_CRASHING_PROCESS_NAME)
                        && !SoftRebootHealthPolicy.PROPERTIES.contains(
                                SoftRebootHealthPolicy.PROP_DEV_ATTEMPTING_REBOOT), null);
        check("the record carries the crashing process name beside the boolean",
                pre().contains("pre_sys_init_updatable_crashing_process_name="), null);

        // --- unreadable, and the null snapshot -------------------------------
        for (String property : SoftRebootHealthPolicy.PROPERTIES) {
            Snapshot s = with(property, SoftRebootHealthPolicy.UNKNOWN);
            check("unreadable " + property + " refuses",
                    SoftRebootHealthPolicy.HEALTH_UNKNOWN.equals(
                            SoftRebootHealthPolicy.verdict(s)),
                    SoftRebootHealthPolicy.verdict(s));
        }
        verdictIs("a snapshot in which nothing could be read",
                SoftRebootHealthPolicy.unreadableSnapshot(-1L, -1L),
                SoftRebootHealthPolicy.HEALTH_UNKNOWN);
        verdictIs("no snapshot at all", null, SoftRebootHealthPolicy.HEALTH_UNKNOWN);
        Snapshot partialSnapshot = new Snapshot();
        partialSnapshot.put(SoftRebootHealthPolicy.PROP_SYS_BOOT_COMPLETED, "1");
        verdictIs("a snapshot missing most properties", partialSnapshot,
                SoftRebootHealthPolicy.HEALTH_UNKNOWN);

        // --- the pre half proves the exec was REACHED, never dispatched ------
        Observation preOnly = SoftRebootHealthPolicy.observe(pre(), BOOT);
        check("a pre-exec record claims nothing about the exec",
                SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY.equals(preOnly.state)
                        && SoftRebootHealthPolicy.CONVERGED.equals(preOnly.preVerdict)
                        && SoftRebootHealthPolicy.EXEC_NOT_REACHED.equals(preOnly.execOutcome)
                        && preOnly.postVerdict == null
                        && preOnly.postObservations == 0
                        && !preOnly.postWindowClosed,
                preOnly.state + " exec=" + preOnly.execOutcome);
        for (String outcome : new String[] {
                SoftRebootHealthPolicy.EXEC_NOT_ATTEMPTED,
                SoftRebootHealthPolicy.EXEC_REFUSED_DIGEST,
                SoftRebootHealthPolicy.EXEC_TRANSPORT_LOST,
                SoftRebootHealthPolicy.EXEC_UNDETERMINED,
                SoftRebootHealthPolicy.EXEC_FAILED,
                SoftRebootHealthPolicy.EXEC_RETURNED }) {
            String updated = SoftRebootHealthPolicy.formatExecOutcome(pre(), BOOT, outcome);
            Observation o = SoftRebootHealthPolicy.observe(updated, BOOT);
            check("exec outcome " + outcome + " is recorded without a post half",
                    updated != null && outcome.equals(o.execOutcome)
                            && SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY.equals(o.state),
                    o.execOutcome);
        }
        check("the exec outcome is written once, never twice",
                SoftRebootHealthPolicy.formatExecOutcome(
                        SoftRebootHealthPolicy.formatExecOutcome(pre(), BOOT,
                                SoftRebootHealthPolicy.EXEC_FAILED),
                        BOOT, SoftRebootHealthPolicy.EXEC_RETURNED) == null, null);
        check("NOT_REACHED cannot be reported as an observed outcome",
                SoftRebootHealthPolicy.formatExecOutcome(pre(), BOOT,
                        SoftRebootHealthPolicy.EXEC_NOT_REACHED) == null, null);
        check("an exec outcome this build does not know refuses",
                SoftRebootHealthPolicy.formatExecOutcome(pre(), BOOT, "PROBABLY_FINE") == null,
                null);
        check("no exec outcome over another boot's record",
                SoftRebootHealthPolicy.formatExecOutcome(pre(), OTHER_BOOT,
                        SoftRebootHealthPolicy.EXEC_FAILED) == null, null);
        malformed("a record with no exec_outcome key at all refuses",
                pre().replace("exec_outcome=NOT_REACHED\n", ""));

        // --- stale, absent, unreadable, malformed, other schema --------------
        Observation stale = SoftRebootHealthPolicy.observe(pre(), OTHER_BOOT);
        check("a record from an earlier boot is STALE_BOOT, not ABSENT",
                SoftRebootHealthPolicy.OBS_STALE_BOOT.equals(stale.state), stale.state);
        check("no record at all is ABSENT",
                SoftRebootHealthPolicy.OBS_ABSENT.equals(
                        SoftRebootHealthPolicy.observe(null, BOOT).state), null);
        check("an unreadable record is its own state",
                SoftRebootHealthPolicy.OBS_UNREADABLE.equals(
                        SoftRebootHealthPolicy.observe(
                                AutoRootPolicy.RECORD_UNREADABLE, BOOT).state), null);
        // A record the app version before this one wrote is intact, not corrupt.
        check("a record with no schema line is OTHER_SCHEMA, not MALFORMED",
                SoftRebootHealthPolicy.OBS_OTHER_SCHEMA.equals(
                        SoftRebootHealthPolicy.observe(
                                pre().replace("schema_version=2\n", ""), BOOT).state), null);
        check("a record from a future schema is OTHER_SCHEMA",
                SoftRebootHealthPolicy.OBS_OTHER_SCHEMA.equals(
                        SoftRebootHealthPolicy.observe(
                                pre().replace("schema_version=2", "schema_version=99"),
                                BOOT).state), null);
        check("a truncated record of this schema is still MALFORMED",
                SoftRebootHealthPolicy.OBS_MALFORMED.equals(
                        SoftRebootHealthPolicy.observe("schema_version=2\nphase=PRE_EXEC\n",
                                BOOT).state), null);

        // --- a stored verdict must be re-derivable from the stored evidence --
        // Without this the file could assert a verdict its own properties refute:
        // a verdict with no evidence behind it (AGENTS.md section 2).
        malformed("a stored CONVERGED over a zeroed platform flag refuses",
                pre().replace("pre_dev_platform_bootcomplete=1",
                        "pre_dev_platform_bootcomplete=0"));
        malformed("a stored CONVERGED over a restarting zygote refuses",
                pre().replace("pre_init_svc_zygote=running",
                        "pre_init_svc_zygote=restarting"));
        malformed("a stored CONVERGED over an active CrashRecovery refuses",
                pre().replace("pre_crashrecovery_attempting_reboot=ABSENT",
                        "pre_crashrecovery_attempting_reboot=true"));
        malformed("a verdict this build does not write refuses",
                pre().replace("pre_verdict=" + SoftRebootHealthPolicy.CONVERGED,
                        "pre_verdict=BOOT_HEALTH_FINE"));
        check("a half rewritten consistently still parses",
                SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY.equals(
                        SoftRebootHealthPolicy.observe(
                                pre().replace("pre_dev_platform_bootcomplete=1",
                                              "pre_dev_platform_bootcomplete=0")
                                     .replace("pre_verdict="
                                              + SoftRebootHealthPolicy.CONVERGED,
                                              "pre_verdict="
                                              + SoftRebootHealthPolicy.PENDING),
                                BOOT).state), null);

        // --- numeric domains -------------------------------------------------
        malformed("a non-numeric timestamp refuses",
                pre().replace("pre_read_start_ms=41000", "pre_read_start_ms=banana"));
        malformed("a non-numeric pid refuses",
                pre().replace("pre_pid=3028", "pre_pid=nonsense"));
        malformed("a negative number is not a spelling of UNKNOWN and refuses",
                pre().replace("pre_pid=3028", "pre_pid=-1"));
        malformed("a sweep cannot end before it began",
                pre().replace("pre_read_end_ms=41004", "pre_read_end_ms=40000"));
        check("an explicitly UNKNOWN reading still parses",
                SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY.equals(
                        SoftRebootHealthPolicy.observe(
                                pre().replace("pre_pid=3028", "pre_pid=UNKNOWN"),
                                BOOT).state), null);
        check("an all-unreadable snapshot round-trips",
                SoftRebootHealthPolicy.observe(
                        SoftRebootHealthPolicy.formatPreExec(BOOT,
                                SoftRebootHealthPolicy.unreadableSnapshot(-1L, -1L)),
                        BOOT).state.equals(SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY), null);

        // --- the window closes on TIME, never on a verdict -------------------
        // The correction this design exists for: the incident's device had a
        // converged-looking userspace for minutes before CrashRecovery rolled it
        // back, so a first CONVERGED must not end the observation.
        Snapshot transientPending = healthy();
        transientPending.put(SoftRebootHealthPolicy.PROP_DEV_PLATFORM_BOOTCOMPLETE, "0");
        transientPending.put(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER_BOOTC, "running");
        transientPending.readStartMs = 95_000L;
        transientPending.readEndMs = 95_120L;
        transientPending.pid = 7711L;
        transientPending.procStarttime = 94_000L;
        String first = SoftRebootHealthPolicy.formatPostExec(
                pre(), BOOT, transientPending, false);
        Observation firstObs = SoftRebootHealthPolicy.observe(first, BOOT);
        check("the first post observation leaves the window open",
                SoftRebootHealthPolicy.OBS_POST_EXEC.equals(firstObs.state)
                        && SoftRebootHealthPolicy.PENDING.equals(firstObs.postVerdict)
                        && firstObs.postObservations == 1 && !firstObs.postWindowClosed
                        && !firstObs.convergedSeen && !firstObs.crashRecoverySeen,
                firstObs.postVerdict + " n=" + firstObs.postObservations);
        Snapshot converged = healthy();
        converged.readStartMs = 110_000L;
        converged.readEndMs = 110_030L;
        converged.pid = 7711L;
        converged.procStarttime = 94_000L;
        String second = SoftRebootHealthPolicy.formatPostExec(first, BOOT, converged, false);
        Observation secondObs = SoftRebootHealthPolicy.observe(second, BOOT);
        check("a CONVERGED reading does NOT close the window",
                second != null
                        && SoftRebootHealthPolicy.CONVERGED.equals(secondObs.postVerdict)
                        && SoftRebootHealthPolicy.PENDING.equals(secondObs.postFirstVerdict)
                        && secondObs.postObservations == 2
                        && !secondObs.postWindowClosed
                        && secondObs.convergedSeen,
                secondObs.postFirstVerdict + " -> " + secondObs.postVerdict
                        + " closed=" + secondObs.postWindowClosed);
        // ... and the rollback that arrives after it is still recordable.
        Snapshot crashing = healthy();
        crashing.put(SoftRebootHealthPolicy.PROP_CRASHRECOVERY_ATTEMPTING_REBOOT, "true");
        crashing.readStartMs = 230_000L;
        crashing.readEndMs = 230_050L;
        crashing.pid = 7711L;
        crashing.procStarttime = 94_000L;
        String third = SoftRebootHealthPolicy.formatPostExec(second, BOOT, crashing, true);
        Observation thirdObs = SoftRebootHealthPolicy.observe(third, BOOT);
        check("a rollback after a CONVERGED keeps BOTH facts",
                third != null
                        && SoftRebootHealthPolicy.CRASH_RECOVERY.equals(thirdObs.postVerdict)
                        && thirdObs.convergedSeen && thirdObs.crashRecoverySeen
                        && thirdObs.postObservations == 3 && thirdObs.postWindowClosed,
                "converged_seen=" + thirdObs.convergedSeen
                        + " crash_seen=" + thirdObs.crashRecoverySeen);
        check("a closed window accepts no further observation",
                SoftRebootHealthPolicy.formatPostExec(third, BOOT, healthy(), false) == null,
                null);
        String deadlined = SoftRebootHealthPolicy.formatPostExec(
                first, BOOT, transientPending, true);
        Observation deadlinedObs = SoftRebootHealthPolicy.observe(deadlined, BOOT);
        check("PENDING with the window closed is the minutes-long failure",
                SoftRebootHealthPolicy.PENDING.equals(deadlinedObs.postVerdict)
                        && deadlinedObs.postWindowClosed && !deadlinedObs.convergedSeen,
                deadlinedObs.postVerdict);
        check("the exec outcome survives the post half",
                SoftRebootHealthPolicy.EXEC_NOT_REACHED.equals(firstObs.execOutcome),
                firstObs.execOutcome);
        check("the post sweep's width is reported, not hidden",
                firstObs.postReadSpanMs == 120L, Long.toString(firstObs.postReadSpanMs));
        malformed("a sticky flag that contradicts the latest verdict refuses",
                second.replace("post_converged_seen=1", "post_converged_seen=0"));
        malformed("a sticky flag outside its domain refuses",
                first.replace("post_crash_recovery_seen=0", "post_crash_recovery_seen=maybe"));
        malformed("a non-numeric observation count refuses",
                first.replace("post_observations=1", "post_observations=many"));
        malformed("a zero observation count refuses",
                first.replace("post_observations=1", "post_observations=0"));
        malformed("post_settled is a boolean; anything else refuses",
                first.replace("post_settled=0", "post_settled=maybe"));
        malformed("a first verdict this build does not write refuses",
                first.replace("post_first_verdict=" + SoftRebootHealthPolicy.PENDING,
                        "post_first_verdict=BOOT_HEALTH_FINE"));

        // --- process identity: an equal pid is not evidence of survival ------
        check("a changed pid settles it",
                SoftRebootHealthPolicy.PROC_REPLACED.equals(firstObs.processIdentity),
                firstObs.processIdentity);
        Snapshot reusedPid = healthy();
        reusedPid.pid = 3028L;              // the pre half's pid, reused
        reusedPid.procStarttime = 94_000L;  // but a different generation
        check("an equal pid with a different start time is still REPLACED",
                SoftRebootHealthPolicy.PROC_REPLACED.equals(
                        SoftRebootHealthPolicy.observe(
                                SoftRebootHealthPolicy.formatPostExec(
                                        pre(), BOOT, reusedPid, false), BOOT).processIdentity),
                null);
        Snapshot sameProc = healthy();
        sameProc.pid = 3028L;
        sameProc.procStarttime = 9_100L;
        check("an equal pid AND start time is the same process",
                SoftRebootHealthPolicy.PROC_SAME.equals(
                        SoftRebootHealthPolicy.observe(
                                SoftRebootHealthPolicy.formatPostExec(
                                        pre(), BOOT, sameProc, false), BOOT).processIdentity),
                null);
        Snapshot noStart = healthy();
        noStart.pid = 3028L;
        noStart.procStarttime = -1L;
        check("an equal pid with no start time is UNDECIDED, never 'same process'",
                SoftRebootHealthPolicy.PROC_UNDECIDED.equals(
                        SoftRebootHealthPolicy.observe(
                                SoftRebootHealthPolicy.formatPostExec(
                                        pre(), BOOT, noStart, false), BOOT).processIdentity),
                null);

        // --- the post half must refuse everything that is not its own record -
        check("no post half over another boot's record",
                SoftRebootHealthPolicy.formatPostExec(pre(), OTHER_BOOT, healthy(), false)
                        == null, null);
        check("no post half with no record at all",
                SoftRebootHealthPolicy.formatPostExec(null, BOOT, healthy(), false) == null,
                null);
        check("no post half without a current boot_id",
                SoftRebootHealthPolicy.formatPostExec(pre(), "", healthy(), false) == null,
                null);
        check("no post half over a malformed record",
                SoftRebootHealthPolicy.formatPostExec("schema_version=2\nboot_id=" + BOOT + "\n",
                        BOOT, healthy(), false) == null, null);

        // --- the parser is strict in both directions -------------------------
        malformed("an unknown key refuses", pre() + "extra=1\n");
        malformed("a duplicate key refuses", pre() + "pre_pid=9\n");
        malformed("a dropped key refuses",
                pre().replace("pre_dev_bootcomplete=1\n", ""));
        malformed("post_* keys on a PRE_EXEC record refuse", pre() + "post_pid=9\n");
        malformed("a POST_EXEC phase without a post half refuses",
                pre().replace("phase=PRE_EXEC", "phase=POST_EXEC"));
        malformed("a phase this build does not write refuses",
                pre().replace("phase=PRE_EXEC", "phase=MID_EXEC"));
        malformed("an empty boot_id refuses",
                pre().replace("boot_id=" + BOOT, "boot_id="));
        malformed("a line with no value refuses", pre() + "pre_note\n");

        System.out.println("");
        System.out.println("SoftRebootHealthPolicyTest: " + pass + "/" + (pass + fail)
                + " passed");
        if (fail != 0) System.exit(1);
    }
}
