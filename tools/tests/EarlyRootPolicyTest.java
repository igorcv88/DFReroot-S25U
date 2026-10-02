import com.polygraphene.df.reroot.AutoRootPolicy;
import com.polygraphene.df.reroot.EarlyBootProbePolicy;
import com.polygraphene.df.reroot.EarlyRootPolicy;

/**
 * Host regression suite for the Early Integrated Root policy.
 *
 * Every case here is one the device cannot be asked to reproduce on demand, and
 * most of them cost a full reboot to reach even once: a callback that fires in
 * the boot it was armed in, a persisted job restored minutes after the early
 * window closed, an app update between the arming and the boot, a journal left
 * behind by a run that died after transaction 5, a `/dev/df*` probe that answers
 * EACCES rather than ENOENT. The policy is pure precisely so these stay
 * testable, and a gate that cannot fail is not a gate - so each element gets its
 * own negative case.
 */
public class EarlyRootPolicyTest {

    private static int pass = 0;
    private static int fail = 0;

    private static final int CODE = 8;
    private static final String NAME = "2.0.15-zzic";
    private static final String KSUD =
            "d0cb516da0047b1b918f84adf8ce7a389c6285de9282cd6301514a40849af7fc";
    private static final String FP =
            "samsung/zzic/pa3q:17/BP4A.250505.005/S938BXXUCZZIC:user/release-keys";
    private static final String QUAL_BOOT = "0643a5e2-9a44-4bb9-b7a4-31a3b255e3ac";
    private static final String ARMED_BOOT = "aaaaaaaa-1111-2222-3333-444444444444";
    private static final String BOOT = "bbbbbbbb-5555-6666-7777-888888888888";
    private static final String NS = EarlyRootPolicy.EXPECTED_NAMESPACE;

    private static void check(boolean ok, String what) {
        if (ok) {
            pass++;
            System.out.println("  ok   - " + what);
        } else {
            fail++;
            System.out.println("  FAIL - " + what);
        }
    }

    private static String qualification() {
        return AutoRootPolicy.formatQualification(CODE, NAME, KSUD, FP, QUAL_BOOT,
                1759000000000L, false, QUAL_BOOT);
    }

    private static String arm() {
        return EarlyRootPolicy.formatArm(ARMED_BOOT, EarlyRootPolicy.EXPECTED_JOB_ID,
                NS, 15_000L, 1, CODE, NAME, KSUD, FP, 300_000L, 1759000000000L);
    }

    /** Every element satisfied; each test below spoils exactly one. */
    private static EarlyRootPolicy.Inputs ready() {
        EarlyRootPolicy.Inputs in = new EarlyRootPolicy.Inputs();
        in.armRecord = arm();
        in.journalRecord = null;
        in.qualificationRecord = qualification();
        in.currentBootId = BOOT;
        in.callbackJobId = EarlyRootPolicy.EXPECTED_JOB_ID;
        in.callbackNamespace = NS;
        in.expectedNamespace = NS;
        in.readinessState = EarlyBootProbePolicy.NETWORKSTACK_READY;
        in.callbackElapsedMs = 15_300L;   // the captured boots: 14.6-17.1 s
        in.markerState = AutoRootPolicy.MARKER_ABSENT;
        in.liveSelinux = 1;
        in.versionCode = CODE;
        in.versionName = NAME;
        in.ksudSha256 = KSUD;
        in.deviceFingerprint = FP;
        return in;
    }

    private static void allowed(EarlyRootPolicy.Inputs in, String what) {
        EarlyRootPolicy.Decision d = EarlyRootPolicy.evaluate(in);
        check(d.allow, what + " (reason=" + d.reason + ")");
    }

    private static void refused(EarlyRootPolicy.Inputs in, String code, String what) {
        EarlyRootPolicy.Decision d = EarlyRootPolicy.evaluate(in);
        check(!d.allow && code.equals(d.code),
                what + " (code=" + d.code + " reason=" + d.reason + ")");
    }

    public static void main(String[] args) {
        System.out.println("[T] EarlyRootPolicy");

        // --- the arm record --------------------------------------------------
        String record = arm();
        EarlyRootPolicy.Arm parsed = EarlyRootPolicy.parseArm(record);
        check(parsed != null && parsed.jobId == EarlyRootPolicy.EXPECTED_JOB_ID
                        && parsed.armedBootId.equals(ARMED_BOOT)
                        && parsed.versionCode == CODE,
                "a complete arm record parses with its build identity");
        check(EarlyRootPolicy.parseArm(record + "unknown=1\n") == null,
                "an unknown arm key refuses");
        check(EarlyRootPolicy.parseArm(record + "job_id=7\n") == null,
                "a duplicate arm key refuses");
        check(EarlyRootPolicy.parseArm(
                        record.replace("ksud_sha256=" + KSUD + "\n", "")) == null,
                "a missing arm key refuses");
        check(EarlyRootPolicy.parseArm(
                        record.replace("schedule_result=1", "schedule_result=0")) == null,
                "a failed schedule result cannot become an arming");
        check(EarlyRootPolicy.parseArm(
                        record.replace("minimum_latency_ms=15000",
                                "minimum_latency_ms=0")) == null,
                "a zero latency is not an arming of a delayed job");
        check(EarlyRootPolicy.parseArm(
                        record.replace("armed_elapsed_ms=300000",
                                "armed_elapsed_ms=-1")) == null,
                "an arm record whose clock failed cannot place itself in its boot");
        check(EarlyRootPolicy.parseArm(
                        record.replace("job_id=" + EarlyRootPolicy.EXPECTED_JOB_ID,
                                "job_id=12345")) == null,
                "an arm record naming another job id refuses");
        check(EarlyRootPolicy.parseArm(
                        record.replace("namespace=" + NS, "namespace=someone-else"))
                        == null,
                "a third namespace both fields could agree on still refuses");
        check(EarlyRootPolicy.parseArm(
                        record.replace("state=" + EarlyRootPolicy.STATE_ARMED,
                                "state=SOMETHING")) == null,
                "an arm record in another state refuses");
        check(EarlyRootPolicy.parseArm(AutoRootPolicy.RECORD_UNREADABLE) == null,
                "an unreadable arm record never parses");
        check(EarlyRootPolicy.parseArm(null) == null && EarlyRootPolicy.parseArm("") == null,
                "an absent arm record never parses");

        // --- the journal -----------------------------------------------------
        String journal = EarlyRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_STARTED, 1, true);
        EarlyRootPolicy.Journal j = EarlyRootPolicy.parseJournal(journal);
        check(j != null && j.nativeStarted && j.attempts == 1
                        && AutoRootPolicy.PHASE_STARTED.equals(j.phase),
                "a complete journal parses");
        check(EarlyRootPolicy.parseJournal(journal + "extra=1\n") == null,
                "an unknown journal key refuses");
        check(EarlyRootPolicy.parseJournal(
                        journal.replace("phase=" + AutoRootPolicy.PHASE_STARTED,
                                "phase=HALFWAY")) == null,
                "a journal phase this build does not know refuses rather than"
                        + " falling through");
        check(EarlyRootPolicy.parseJournal(
                        journal.replace("native_started=1", "native_started=2")) == null,
                "a native_started that is neither 0 nor 1 refuses");
        check(EarlyRootPolicy.parseJournal(
                        journal.replace("attempts=1", "attempts=-1")) == null,
                "a negative attempt count refuses");
        check(EarlyRootPolicy.parseJournal(AutoRootPolicy.RECORD_UNREADABLE) == null,
                "an unreadable journal never parses");

        // --- the durable trace ----------------------------------------------
        String line = EarlyRootPolicy.formatTraceStep(
                EarlyRootPolicy.STEP_BEFORE_NATIVE, BOOT, 15_800L,
                "sys_boot_completed=UNKNOWN", "transaction 5 about to be issued");
        EarlyRootPolicy.TraceStep step = EarlyRootPolicy.parseTraceLine(line);
        check(step != null && EarlyRootPolicy.STEP_BEFORE_NATIVE.equals(step.step)
                        && step.elapsedMs == 15_800L && BOOT.equals(step.bootId),
                "a trace step round-trips through its own parser");
        check(EarlyRootPolicy.parseTraceLine(
                        EarlyRootPolicy.formatTraceStep("EARLY_ROOT_INVENTED", BOOT,
                                1L, "x", "y")) == null,
                "a step outside the closed vocabulary refuses, so a typo cannot"
                        + " become a line nobody can account for");
        check(EarlyRootPolicy.parseTraceLine(
                        EarlyRootPolicy.formatTraceStep(
                                EarlyRootPolicy.STEP_JOB_ENTERED, BOOT, -1L, "x", "y"))
                        == null,
                "a step whose clock could not be read orders nothing and refuses");
        check(EarlyRootPolicy.parseTraceLine("a\tb\tc") == null,
                "a truncated trace line refuses");
        // The staging step says STAGING, not STAGED: the coordinator reports
        // that phase before staging is attempted and before its digest check,
        // so the old name was false in exactly the failing runs.
        check(EarlyRootPolicy.STEP_KSUD_STAGING.endsWith("STAGING")
                        && EarlyRootPolicy.parseTraceLine(
                                EarlyRootPolicy.formatTraceStep(
                                        EarlyRootPolicy.STEP_KSUD_STAGING, BOOT, 5L,
                                        "x", "y")) != null,
                "the ksud step is a pre-record and is in the vocabulary");
        check(EarlyRootPolicy.parseTraceLine(
                        EarlyRootPolicy.formatTraceStep(
                                "EARLY_ROOT_KSUD_STAGED", BOOT, 5L, "x", "y")) == null,
                "the old STAGED spelling is gone from the vocabulary, so a stale"
                        + " writer cannot resurrect the false claim");
        check(!EarlyRootPolicy.STEP_STAGEHOP_SENDING.equals(
                        EarlyRootPolicy.STEP_STAGEHOP_SENT)
                        && EarlyRootPolicy.parseTraceLine(
                                EarlyRootPolicy.formatTraceStep(
                                        EarlyRootPolicy.STEP_STAGEHOP_SENDING, BOOT,
                                        6L, "x", "y")) != null,
                "the hop has a pre-record step distinct from its post-record one:"
                        + " WAIT_CONTROLLER is only reported after the hop returned");
        check(EarlyRootPolicy.parseTraceLine(
                        EarlyRootPolicy.STEP_JOB_ENTERED + "\t" + BOOT
                                + "\tnotanumber\tx\ty") == null,
                "a trace line with a non-numeric timestamp refuses");
        check(EarlyRootPolicy.parseTraceLine(
                        EarlyRootPolicy.STEP_JOB_ENTERED + "\t\t5\tx\ty") == null,
                "a trace line with no boot id refuses");
        // The writer sanitises, so a detail holding a tab cannot add a field and
        // make the next line's parse succeed against the wrong columns.
        EarlyRootPolicy.TraceStep sanitised = EarlyRootPolicy.parseTraceLine(
                EarlyRootPolicy.formatTraceStep(EarlyRootPolicy.STEP_FAILED, BOOT,
                        9L, "x", "a\tb\nc"));
        check(sanitised != null && sanitised.detail.equals("a b c"),
                "tabs and newlines in a detail are sanitised, not allowed to"
                        + " re-shape the record");

        String trace = line
                + EarlyRootPolicy.formatTraceStep(EarlyRootPolicy.STEP_FAILED, BOOT,
                        16_000L, "x", "y");
        check(EarlyRootPolicy.traceStepCount(trace) == 2,
                "the step count counts accountable lines");
        check(EarlyRootPolicy.traceStepCount(trace + "garbage\n") == 2,
                "an unaccountable line is not counted");
        check(EarlyRootPolicy.traceBelongsToBoot(trace, BOOT),
                "a trace opening on this boot belongs to it");
        check(!EarlyRootPolicy.traceBelongsToBoot(trace, ARMED_BOOT),
                "a trace opening on another boot does not belong to this one");
        check(!EarlyRootPolicy.traceBelongsToBoot(
                        EarlyRootPolicy.formatTraceStep(EarlyRootPolicy.STEP_JOB_ENTERED,
                                ARMED_BOOT, 1L, "x", "y") + line, BOOT),
                "ownership follows the FIRST accountable line, so a record cannot"
                        + " span two boots by appending to it");
        check(!EarlyRootPolicy.traceBelongsToBoot("garbage\n", BOOT),
                "a trace with no accountable line belongs to no boot");
        check(!EarlyRootPolicy.traceBelongsToBoot(
                        AutoRootPolicy.RECORD_UNREADABLE, BOOT),
                "an unreadable trace is never claimed by this boot");
        StringBuilder full = new StringBuilder();
        for (int i = 0; i < EarlyRootPolicy.MAX_TRACE_STEPS; i++) {
            full.append(EarlyRootPolicy.formatTraceStep(
                    EarlyRootPolicy.STEP_JOB_ENTERED, BOOT, i, "x", "y"));
        }
        check(EarlyRootPolicy.traceHasRoom(trace)
                        && !EarlyRootPolicy.traceHasRoom(full.toString()),
                "the per-boot trace is bounded; something re-entering cannot grow"
                        + " it without limit");

        // --- the gate, element by element ------------------------------------
        allowed(ready(), "every element satisfied allows one early attempt");

        EarlyRootPolicy.Inputs in = ready();
        in.currentBootId = "";
        refused(in, EarlyRootPolicy.NO_BOOT_ID,
                "a boot that cannot be named refuses: same-boot evidence would be"
                        + " impossible");

        in = ready();
        in.armRecord = null;
        refused(in, EarlyRootPolicy.ARM_NO_RECORD,
                "an unarmed device refuses, and absence is not agreement");

        in = ready();
        in.armRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in, EarlyRootPolicy.ARM_UNREADABLE,
                "an arm record that exists and cannot be read refuses as its own"
                        + " fact, not as 'not armed'");

        in = ready();
        in.armRecord = arm() + "junk\n";
        refused(in, EarlyRootPolicy.ARM_MALFORMED, "a malformed arm record refuses");

        in = ready();
        in.currentBootId = ARMED_BOOT;
        refused(in, EarlyRootPolicy.ARM_SAME_BOOT,
                "a callback in the arming boot refuses: a framework restart keeps"
                        + " boot_id and is not a full reboot");

        in = ready();
        in.callbackJobId = 999;
        refused(in, EarlyRootPolicy.BINDING_MISMATCH,
                "a callback for another job id refuses; uid 1000 is shared");

        in = ready();
        in.callbackNamespace = EarlyRootPolicy.DEFAULT_UID_NAMESPACE;
        refused(in, EarlyRootPolicy.BINDING_MISMATCH,
                "a callback in another namespace refuses even when our record is"
                        + " self-consistent");

        in = ready();
        in.expectedNamespace = EarlyRootPolicy.DEFAULT_UID_NAMESPACE;
        refused(in, EarlyRootPolicy.BINDING_MISMATCH,
                "an arming made under a different platform namespace refuses after"
                        + " an OS upgrade changes what this runtime would arm");

        in = ready();
        in.versionCode = CODE + 1;
        refused(in, EarlyRootPolicy.BUILD_MISMATCH,
                "an app update between the arming and the boot refuses");

        in = ready();
        in.versionName = NAME + "-x";
        refused(in, EarlyRootPolicy.BUILD_MISMATCH, "a version-name change refuses");

        in = ready();
        in.ksudSha256 = KSUD.replace('d', 'e');
        refused(in, EarlyRootPolicy.BUILD_MISMATCH,
                "a repinned daemon refuses even when the app version did not move");

        in = ready();
        in.deviceFingerprint = FP + "/other";
        refused(in, EarlyRootPolicy.BUILD_MISMATCH, "a firmware update refuses");

        in = ready();
        in.qualificationRecord = null;
        refused(in, EarlyRootPolicy.NOT_QUALIFIED,
                "a build whose chain has never completed manually refuses; the early"
                        + " window is not where that is discovered");

        in = ready();
        in.qualificationRecord = AutoRootPolicy.formatQualification(CODE + 1, NAME,
                KSUD, FP, QUAL_BOOT, 1759000000000L, true, QUAL_BOOT);
        refused(in, EarlyRootPolicy.NOT_QUALIFIED,
                "a qualification recorded for another build does not qualify this one");

        in = ready();
        in.qualificationRecord = AutoRootPolicy.formatQualification(CODE, NAME, KSUD,
                FP, QUAL_BOOT, 1759000000000L, true, QUAL_BOOT);
        allowed(in, "Auto Root's opt_in flag is not consulted: arming is Early"
                + " Root's own opt-in, so opt_in=1 changes nothing");

        in = ready();
        in.callbackElapsedMs = -1;
        refused(in, EarlyRootPolicy.CLOCK_UNAVAILABLE,
                "a callback that cannot be placed in the early window refuses");

        in = ready();
        in.callbackElapsedMs = EarlyRootPolicy.EARLY_WINDOW_MS + 1;
        refused(in, EarlyRootPolicy.PAST_WINDOW,
                "a persisted job restored past the early window refuses instead of"
                        + " becoming a second Auto Root");

        in = ready();
        in.callbackElapsedMs = EarlyRootPolicy.EARLY_WINDOW_MS;
        allowed(in, "the window boundary itself is inside it");

        in = ready();
        in.journalRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in, EarlyRootPolicy.JOURNAL_UNREADABLE,
                "an unreadable journal is the worst case, not a blank slate: it may"
                        + " say STARTED");

        in = ready();
        in.journalRecord = "boot_id=" + BOOT + "\n";
        refused(in, EarlyRootPolicy.JOURNAL_MALFORMED,
                "a journal from a run that died mid-write refuses");

        for (String phase : new String[] {AutoRootPolicy.PHASE_PREFLIGHT,
                AutoRootPolicy.PHASE_STARTED, AutoRootPolicy.PHASE_COMPLETE,
                AutoRootPolicy.PHASE_FAILED_LOCKED}) {
            in = ready();
            in.journalRecord = EarlyRootPolicy.formatJournal(BOOT, phase, 1,
                    AutoRootPolicy.PHASE_STARTED.equals(phase));
            refused(in, EarlyRootPolicy.BOOT_SPENT,
                    "a second entry in a boot already at phase " + phase + " refuses");
        }

        in = ready();
        in.journalRecord = EarlyRootPolicy.formatJournal(ARMED_BOOT,
                AutoRootPolicy.PHASE_COMPLETE, 1, true);
        allowed(in, "a journal naming another boot says nothing about this one and"
                + " must not lock it");

        // --- the other trigger's journal, in this direction too --------------
        // Auto Root is triggered by LOCKED_BOOT_COMPLETED (17.6-19.7 s on this
        // device) and a persisted job can be restored any time inside the 120 s
        // window, so Auto Root can reach transaction 5 FIRST. If its native side
        // failed before stage1 created /dev/df, the marker probe answers a clean
        // ENOENT and the run guard has been released - so without this check
        // every remaining condition passes and a second native transaction runs
        // in a boot whose page cache may already have been written. None of this
        // is reachable on a device: it needs a failed Auto Root attempt that
        // wrote no marker plus a late job restore in the same boot.
        in = ready();
        in.autoRootJournalRecord = null;
        allowed(in, "no Auto Root journal grants nothing and removes nothing");

        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in, EarlyRootPolicy.AUTO_JOURNAL_UNREADABLE,
                "an unreadable Auto Root journal refuses; it may say STARTED");

        in = ready();
        in.autoRootJournalRecord = "boot_id=" + BOOT + "\n";
        refused(in, EarlyRootPolicy.AUTO_JOURNAL_MALFORMED,
                "a malformed Auto Root journal refuses");

        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_FAILED_LOCKED, 1, true);
        refused(in, EarlyRootPolicy.AUTO_BOOT_SPENT,
                "the interleaving this exists for: Auto Root issued transaction 5,"
                        + " failed before any /dev/df marker, and the early callback"
                        + " must not run a second one");

        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_STARTED, 1, true);
        refused(in, EarlyRootPolicy.AUTO_BOOT_SPENT,
                "an Auto Root run that began native execution refuses the early"
                        + " dispatch");

        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_COMPLETE, 1, true);
        refused(in, EarlyRootPolicy.AUTO_BOOT_SPENT,
                "an Auto Root run that completed in this boot refuses the early"
                        + " dispatch");

        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_PREFLIGHT, 3, true);
        refused(in, EarlyRootPolicy.AUTO_BOOT_SPENT,
                "native_started=1 outranks a PREFLIGHT phase in this direction too");

        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_PREFLIGHT, 4, false);
        allowed(in, "Auto Root still polling readiness, nothing written: the early"
                + " window is not spent, and the run guard settles the race");

        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.formatJournal(BOOT,
                "HALFWAY", 1, false);
        refused(in, EarlyRootPolicy.AUTO_JOURNAL_MALFORMED,
                "an Auto Root phase this build does not know refuses rather than"
                        + " falling through to allow");

        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.formatJournal(ARMED_BOOT,
                AutoRootPolicy.PHASE_FAILED_LOCKED, 1, true);
        allowed(in, "an Auto Root journal naming another boot says nothing about"
                + " this one and must not lock it");

        // The guard has to hold in both directions or it is 3.2 at the scale of
        // the whole feature: one trigger reading the other and not the reverse.
        AutoRootPolicy.Inputs mirror = new AutoRootPolicy.Inputs();
        mirror.earlyRootJournalRecord = EarlyRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_FAILED_LOCKED, 1, true);
        in = ready();
        in.autoRootJournalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_FAILED_LOCKED, 1, true);
        check(!EarlyRootPolicy.evaluate(in).allow
                        && mirror.earlyRootJournalRecord != null,
                "each trigger refuses on the other's spent boot, not just one of"
                        + " them (AutoRootPolicyTest drives the opposite direction)");

        in = ready();
        in.markerState = AutoRootPolicy.MARKER_PRESENT;
        refused(in, EarlyRootPolicy.MARKER_PRESENT,
                "/dev/df present refuses a second run in this boot");

        in = ready();
        in.markerState = AutoRootPolicy.MARKER_UNKNOWN;
        refused(in, EarlyRootPolicy.MARKER_UNKNOWN,
                "a marker probe that did not answer refuses rather than assuming a"
                        + " clean boot (on this firmware it answers EACCES once rooted)");

        in = ready();
        in.liveSelinux = 0;
        refused(in, EarlyRootPolicy.SELINUX_NOT_ENFORCING,
                "a device already permissive refuses");

        in = ready();
        in.liveSelinux = -1;
        refused(in, EarlyRootPolicy.SELINUX_NOT_ENFORCING,
                "an unreadable SELinux state refuses; -1 is never agreement");

        in = ready();
        in.readinessState = EarlyBootProbePolicy.NETWORKSTACK_PARTIAL;
        refused(in, EarlyRootPolicy.READINESS_REFUSED,
                "PARTIAL readiness refuses: in this window an unresolvable component"
                        + " is indistinguishable from 'too early'");

        in = ready();
        in.readinessState = EarlyBootProbePolicy.NETWORKSTACK_NOT_READY;
        refused(in, EarlyRootPolicy.READINESS_REFUSED, "NOT_READY refuses");

        in = ready();
        in.readinessState = null;
        refused(in, EarlyRootPolicy.READINESS_REFUSED,
                "a readiness state nobody sampled refuses; the pre-readiness stage"
                        + " may skip work, never permit a run");

        // The two-stage split must not become a second gate. Everything the
        // durable stage refuses, the full gate refuses too.
        in = ready();
        in.armRecord = null;
        check(!EarlyRootPolicy.evaluateBeforeReadiness(in).allow
                        && !EarlyRootPolicy.evaluate(in).allow,
                "the cheap pre-readiness stage and the full gate agree on a"
                        + " refusal: evaluate() re-runs all of it");
        in = ready();
        in.markerState = AutoRootPolicy.MARKER_PRESENT;
        check(EarlyRootPolicy.evaluateBeforeReadiness(in).allow
                        && !EarlyRootPolicy.evaluate(in).allow,
                "and the pre-readiness stage alone is not permission: it does not"
                        + " see the observed state");

        // --- the terminal phase, and the R1 correction ------------------------
        check(AutoRootPolicy.PHASE_COMPLETE.equals(
                        EarlyRootPolicy.terminalPhase(true, true)),
                "a verified run records COMPLETE");
        check(AutoRootPolicy.PHASE_FAILED_LOCKED.equals(
                        EarlyRootPolicy.terminalPhase(false, true)),
                "a failure AFTER transaction 5 locks the boot");
        check(AutoRootPolicy.PHASE_PREFLIGHT.equals(
                        EarlyRootPolicy.terminalPhase(false, false)),
                "a failure BEFORE transaction 5 provably wrote nothing, so it does"
                        + " not lock the boot against Auto Root's own trigger");

        check(EarlyRootPolicy.MAX_ATTEMPTS_PER_BOOT == 1,
                "the early path is one attempt per boot: there is no retry loop to"
                        + " bound, and a self-rescheduling root attempt must not exist");
        check(EarlyRootPolicy.EXPECTED_JOB_ID != EarlyBootProbePolicy.EXPECTED_JOB_ID
                        && !EarlyRootPolicy.EXPECTED_NAMESPACE.equals(
                                EarlyBootProbePolicy.EXPECTED_NAMESPACE),
                "the dispatching job is a different job from the observation-only"
                        + " probe, so arming a probe can never reach transaction 5");

        System.out.println("");
        System.out.println("EarlyRootPolicyTest: " + pass + "/" + (pass + fail)
                + " passed");
        if (fail != 0) System.exit(1);
    }
}
