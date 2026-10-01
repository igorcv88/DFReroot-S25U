import com.polygraphene.df.reroot.AutoRootPolicy;
import com.polygraphene.df.reroot.SoftRebootHealthPolicy;
import com.polygraphene.df.reroot.SoftRebootHealthPolicy.Observation;
import com.polygraphene.df.reroot.SoftRebootHealthPolicy.Snapshot;

/**
 * Host tests for the Samsung boot-health policy.
 *
 * Every element of the verdict gets its negative case, because a gate that
 * cannot fail is not a gate (AGENTS.md section 5). None of these states can be
 * produced on demand on a device: `dev.platform_bootcomplete` is zeroed by the
 * firmware's own init trigger during a zygote restart, `bootchecker` is a
 * oneshot service that is `running` only while the watchdog is waiting, and
 * `crashrecovery.attempting_reboot` is set moments before the device reboots.
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
        // Both are unset on a healthy boot, which is a reading, not a failure.
        s.put(SoftRebootHealthPolicy.PROP_CRASHRECOVERY_ATTEMPTING_REBOOT, "");
        s.put(SoftRebootHealthPolicy.PROP_UPDATABLE_CRASHING, null);
        s.elapsedMs = 41_000L;
        s.pid = 3028;
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

    public static void main(String[] args) {
        System.out.println("[T] SoftRebootHealthPolicy");

        // --- the one positive -----------------------------------------------
        verdictIs("healthy ZZIC full boot converges", healthy(),
                SoftRebootHealthPolicy.CONVERGED);

        // --- the three boot-completion flags, one at a time ------------------
        verdictIs("sys.boot_completed not yet 1",
                with(SoftRebootHealthPolicy.PROP_SYS_BOOT_COMPLETED, "0"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("dev.bootcomplete not yet 1",
                with(SoftRebootHealthPolicy.PROP_DEV_BOOTCOMPLETE, "0"),
                SoftRebootHealthPolicy.PENDING);
        /*
         * The exact 2026-10-01 state: bootchecker.rc zeroed this flag on
         * `init.svc.zygote=restarting` and the `on property:dev.bootcomplete=1`
         * trigger that restores it never re-fired.
         */
        verdictIs("dev.platform_bootcomplete zeroed by the zygote-restart trigger",
                with(SoftRebootHealthPolicy.PROP_DEV_PLATFORM_BOOTCOMPLETE, "0"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("dev.platform_bootcomplete unset entirely",
                with(SoftRebootHealthPolicy.PROP_DEV_PLATFORM_BOOTCOMPLETE, ""),
                SoftRebootHealthPolicy.PENDING);

        // --- the services that own the Samsung half --------------------------
        verdictIs("zygote restarting is never a converged boot",
                with(SoftRebootHealthPolicy.PROP_INIT_SVC_ZYGOTE, "restarting"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("bootchecker still running means the watchdog is waiting",
                with(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER, "running"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("bootchecker-bootc still running",
                with(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER_BOOTC, "running"),
                SoftRebootHealthPolicy.PENDING);
        verdictIs("a bootchecker service that never started",
                with(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER, ""),
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
        /*
         * A crash signal that could not be READ must not come back as PENDING,
         * which reads like "just wait". It is the one ordering in verdict() that
         * is load-bearing rather than cosmetic.
         */
        Snapshot unreadableCrash = healthy();
        unreadableCrash.put(SoftRebootHealthPolicy.PROP_SYS_BOOT_COMPLETED, "0");
        unreadableCrash.put(SoftRebootHealthPolicy.PROP_UPDATABLE_CRASHING,
                SoftRebootHealthPolicy.UNKNOWN);
        verdictIs("an unreadable crash signal outranks a pending flag",
                unreadableCrash, SoftRebootHealthPolicy.HEALTH_UNKNOWN);

        // --- unreadable, and the null snapshot -------------------------------
        for (String property : SoftRebootHealthPolicy.PROPERTIES) {
            Snapshot s = with(property, SoftRebootHealthPolicy.UNKNOWN);
            check("unreadable " + property + " refuses",
                    SoftRebootHealthPolicy.HEALTH_UNKNOWN.equals(
                            SoftRebootHealthPolicy.verdict(s)),
                    SoftRebootHealthPolicy.verdict(s));
        }
        verdictIs("a snapshot in which nothing could be read",
                SoftRebootHealthPolicy.unreadableSnapshot(-1L, -1),
                SoftRebootHealthPolicy.HEALTH_UNKNOWN);
        verdictIs("no snapshot at all", null, SoftRebootHealthPolicy.HEALTH_UNKNOWN);
        Snapshot partial = new Snapshot();
        partial.put(SoftRebootHealthPolicy.PROP_SYS_BOOT_COMPLETED, "1");
        verdictIs("a snapshot missing most properties", partial,
                SoftRebootHealthPolicy.HEALTH_UNKNOWN);

        // --- the record: round trip, then every way it must refuse -----------
        String pre = SoftRebootHealthPolicy.formatPreExec(BOOT, healthy());
        Observation preOnly = SoftRebootHealthPolicy.observe(pre, BOOT);
        check("a pre-exec record reads as PRE_EXEC_ONLY",
                SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY.equals(preOnly.state)
                        && SoftRebootHealthPolicy.CONVERGED.equals(preOnly.preVerdict)
                        && preOnly.postVerdict == null,
                preOnly.state);
        /*
         * Soft-reboot artefacts survive a full reboot - the trace and lock from
         * boot 85e3a031 were still on disk in boot 68845faf - so a record naming
         * another boot must read as its own state, never as "no dispatch".
         */
        Observation stale = SoftRebootHealthPolicy.observe(pre, OTHER_BOOT);
        check("a record from an earlier boot is STALE_BOOT, not ABSENT",
                SoftRebootHealthPolicy.OBS_STALE_BOOT.equals(stale.state), stale.state);
        check("no record at all is ABSENT",
                SoftRebootHealthPolicy.OBS_ABSENT.equals(
                        SoftRebootHealthPolicy.observe(null, BOOT).state), null);
        check("an unreadable record is its own state",
                SoftRebootHealthPolicy.OBS_UNREADABLE.equals(
                        SoftRebootHealthPolicy.observe(
                                AutoRootPolicy.RECORD_UNREADABLE, BOOT).state), null);
        check("a record this build did not write is MALFORMED",
                SoftRebootHealthPolicy.OBS_MALFORMED.equals(
                        SoftRebootHealthPolicy.observe("phase=PRE_EXEC\n", BOOT).state), null);

        // The post half: written by the restarted framework, in the same boot.
        Snapshot post = healthy();
        post.put(SoftRebootHealthPolicy.PROP_DEV_PLATFORM_BOOTCOMPLETE, "0");
        post.put(SoftRebootHealthPolicy.PROP_INIT_SVC_BOOTCHECKER, "running");
        post.elapsedMs = 95_000L;
        post.pid = 7711;
        String merged = SoftRebootHealthPolicy.formatPostExec(pre, BOOT, post);
        check("the post half completes the record", merged != null, null);
        Observation complete = SoftRebootHealthPolicy.observe(merged, BOOT);
        check("both halves are reported separately",
                SoftRebootHealthPolicy.OBS_POST_EXEC.equals(complete.state)
                        && SoftRebootHealthPolicy.CONVERGED.equals(complete.preVerdict)
                        && SoftRebootHealthPolicy.PENDING.equals(complete.postVerdict),
                complete.state + " pre=" + complete.preVerdict
                        + " post=" + complete.postVerdict);
        check("a changed pid proves the system process was replaced",
                complete.systemProcessReplaced == 1,
                Integer.toString(complete.systemProcessReplaced));
        Snapshot samePid = healthy();
        samePid.pid = 3028;
        Observation sameProcess = SoftRebootHealthPolicy.observe(
                SoftRebootHealthPolicy.formatPostExec(pre, BOOT, samePid), BOOT);
        check("an unchanged pid is recorded as unchanged, not as unknown",
                sameProcess.systemProcessReplaced == 0,
                Integer.toString(sameProcess.systemProcessReplaced));
        Snapshot noPid = healthy();
        noPid.pid = -1;
        Observation undecidable = SoftRebootHealthPolicy.observe(
                SoftRebootHealthPolicy.formatPostExec(pre, BOOT, noPid), BOOT);
        check("a missing pid is undecidable, not 'same process'",
                undecidable.systemProcessReplaced == -1,
                Integer.toString(undecidable.systemProcessReplaced));

        // --- the post half must refuse everything that is not its own pre half
        check("no post half over another boot's pre half",
                SoftRebootHealthPolicy.formatPostExec(pre, OTHER_BOOT, healthy()) == null, null);
        check("no post half over an already complete record",
                SoftRebootHealthPolicy.formatPostExec(merged, BOOT, healthy()) == null, null);
        check("no post half with no record at all",
                SoftRebootHealthPolicy.formatPostExec(null, BOOT, healthy()) == null, null);
        check("no post half without a current boot_id",
                SoftRebootHealthPolicy.formatPostExec(pre, "", healthy()) == null, null);
        check("no post half over a malformed record",
                SoftRebootHealthPolicy.formatPostExec("phase=PRE_EXEC\nboot_id=" + BOOT + "\n",
                        BOOT, healthy()) == null, null);

        // --- the parser is strict in both directions -------------------------
        check("an unknown key refuses",
                SoftRebootHealthPolicy.observe(pre + "extra=1\n", BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);
        check("a duplicate key refuses",
                SoftRebootHealthPolicy.observe(pre + "pre_pid=9\n", BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);
        check("a dropped key refuses",
                SoftRebootHealthPolicy.observe(
                        pre.replace("pre_dev_bootcomplete=1\n", ""), BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);
        check("post_* keys on a PRE_EXEC record refuse",
                SoftRebootHealthPolicy.observe(pre + "post_pid=9\n", BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);
        check("a POST_EXEC phase without a post half refuses",
                SoftRebootHealthPolicy.observe(
                        pre.replace("phase=PRE_EXEC", "phase=POST_EXEC"), BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);
        check("a phase this build does not write refuses",
                SoftRebootHealthPolicy.observe(
                        pre.replace("phase=PRE_EXEC", "phase=MID_EXEC"), BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);
        check("a verdict this build does not write refuses",
                SoftRebootHealthPolicy.observe(
                        pre.replace("pre_verdict=" + SoftRebootHealthPolicy.CONVERGED,
                                "pre_verdict=BOOT_HEALTH_FINE"), BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);
        check("an empty boot_id refuses",
                SoftRebootHealthPolicy.observe(
                        pre.replace("boot_id=" + BOOT, "boot_id="), BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);
        check("a line with no value refuses",
                SoftRebootHealthPolicy.observe(pre + "pre_note\n", BOOT).state
                        .equals(SoftRebootHealthPolicy.OBS_MALFORMED), null);

        System.out.println("");
        System.out.println("SoftRebootHealthPolicyTest: " + pass + "/" + (pass + fail)
                + " passed");
        if (fail != 0) System.exit(1);
    }
}
