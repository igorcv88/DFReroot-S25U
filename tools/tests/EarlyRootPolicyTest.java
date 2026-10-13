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

    private static final String GEN = "7a1c3e5f90b2d4681357abcdef024680";
    private static final String STALE_GEN = "0011223344556677889900aabbccddee";

    private static String arm() {
        return arm(GEN);
    }

    private static String arm(String generation) {
        return EarlyRootPolicy.formatArm(ARMED_BOOT, EarlyRootPolicy.EXPECTED_JOB_ID,
                NS, 15_000L, 1, CODE, NAME, KSUD, FP, 300_000L, 1759000000000L,
                generation);
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
        in.callbackGeneration = GEN;
        in.expectedNamespace = NS;
        in.readinessState = EarlyBootProbePolicy.NETWORKSTACK_READY;
        in.callbackElapsedMs = 15_300L;   // the captured boots: 14.6-17.1 s
        in.bootCompletedState = EarlyRootPolicy.BOOT_NOT_COMPLETED;
        in.markerState = AutoRootPolicy.MARKER_ABSENT;
        in.liveSelinux = 1;
        in.versionCode = CODE;
        in.versionName = NAME;
        in.ksudSha256 = KSUD;
        in.deviceFingerprint = FP;
        /*
         * The two new elements every dispatch has to name, and the two new
         * records it is weighed against. A fixture that left them unset would
         * refuse on TRIGGER_UNRECOGNISED and nothing below would test anything -
         * which is the failure mode of defaults, so they are set explicitly here
         * and spoiled one at a time in the cases that own them.
         */
        in.trigger = EarlyRootPolicy.TRIGGER_JOB;
        in.role = EarlyRootPolicy.ROLE_DISPATCH;
        in.bootanimState = EarlyRootPolicy.BOOTANIM_RUNNING;
        in.cycleRecord = null;      // nothing has bound this arming yet
        return in;
    }

    /** A cycle record bound to this boot, for this arming, unclaimed. */
    private static String boundCycle() {
        return EarlyRootPolicy.formatCycle(EarlyRootPolicy.CYCLE_BOUND, GEN, BOOT,
                EarlyRootPolicy.TRIGGER_NONE, 15_100L, -1L);
    }

    /** A cycle record claimed by one trigger, in this boot, for this arming. */
    private static String claimedCycle(String trigger, String bootId) {
        return EarlyRootPolicy.formatCycle(EarlyRootPolicy.CYCLE_CLAIMED, GEN,
                bootId, trigger, 15_100L, 15_400L);
    }

    /** The service's side: a claimed run re-deriving the whole gate. */
    private static EarlyRootPolicy.Inputs claimedRun() {
        EarlyRootPolicy.Inputs in = ready();
        in.role = EarlyRootPolicy.ROLE_CLAIMED_RUN;
        in.cycleRecord = claimedCycle(EarlyRootPolicy.TRIGGER_JOB, BOOT);
        return in;
    }

    private static EarlyRootPolicy.Inputs bootCompleted() {
        EarlyRootPolicy.Inputs in = ready();
        in.bootCompletedState = EarlyRootPolicy.BOOT_COMPLETED;
        return in;
    }

    /**
     * The element under test is not an objection.
     *
     * It used to assert `d.allow`, and that stopped being the right assertion
     * when the DZIF panic suspended the early window: this suite's default ZZIC
     * fixture is not on the exact-pair allowlist and ends on
     * ARTEFACT_NOT_AUTHORIZED. Weakening these to "refuses with something" would
     * have thrown away what they test, and asserting `allow` would have required
     * un-suspending the window from a test.
     *
     * So the assertion is the element's actual meaning: EITHER the run is
     * permitted, OR the only thing standing in its way is the artefact
     * suspension. Any other code means this element refused, which is the
     * regression these cases exist to catch - and the assertion keeps holding
     * unchanged when another explicitly authorized pair is added.
     */
    private static void allowed(EarlyRootPolicy.Inputs in, String what) {
        EarlyRootPolicy.Decision d = EarlyRootPolicy.evaluate(in);
        check(d.allow || EarlyRootPolicy.ARTEFACT_NOT_AUTHORIZED.equals(d.code),
                what + " (code=" + d.code + " reason=" + d.reason + ")");
    }

    /**
     * The immutable half allows, i.e. this arming is this boot's to consume.
     *
     * The assertion the cycle-record invariant actually rests on. A transient
     * refusal that reaches {@code evaluateArmBinding} means the dispatcher never
     * binds the arming in the boot that refused, the arm record stays live, and
     * the next boot's broadcast runs unarmed - a one-shot control that is
     * really a standing switch.
     */
    private static void binds(EarlyRootPolicy.Inputs in, String what) {
        EarlyRootPolicy.Decision d = EarlyRootPolicy.evaluateArmBinding(in);
        check(d.allow, what + " (code=" + d.code + " reason=" + d.reason + ")");
    }

    private static void refusedBinding(EarlyRootPolicy.Inputs in, String code,
                                       String what) {
        EarlyRootPolicy.Decision d = EarlyRootPolicy.evaluateArmBinding(in);
        check(!d.allow && code.equals(d.code),
                what + " (code=" + d.code + " reason=" + d.reason + ")");
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
        // Transaction 6's boundary is in the vocabulary, and it is NOT the local
        // gate's step. A trace that could only say CONTROLLER_RECEIVED would
        // read the same for "the remote domain refused, nothing written" and
        // "the process died before transaction 5" (3.7).
        check(EarlyRootPolicy.parseTraceLine(
                        EarlyRootPolicy.formatTraceStep(
                                EarlyRootPolicy.STEP_REMOTE_PREFLIGHT_PASS, BOOT,
                                20L, "x", "remote result=0")) != null,
                "the remote preflight boundary is an accountable step, so writing"
                        + " it does not refuse the step it announces");
        check(!EarlyRootPolicy.STEP_REMOTE_PREFLIGHT_PASS.equals(
                        EarlyRootPolicy.STEP_PREFLIGHT_PASS),
                "the remote preflight is a different fact from this process's own"
                        + " local gate, and carries a different step");
        check(EarlyRootPolicy.parseTraceLine(
                        EarlyRootPolicy.formatTraceStep("EARLY_ROOT_PREFLIGHT_OK",
                                BOOT, 20L, "x", "y")) == null,
                "a step name outside the closed vocabulary is unaccountable, so a"
                        + " typo refuses instead of logging a line nobody can place");

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

        // --- the arming is one operation, and the token is what says so ------
        // schedule() and the durable arm record cannot be atomic. The reachable
        // state: the process dies after the new job is persisted and before the
        // new record replaces the old one, so the next boot finds a NEW job
        // beside an OLD authorisation. Every other field still agrees, because
        // none of them identify the arming - and the stale record names an
        // earlier boot, so ARM_SAME_BOOT does not fire either.
        in = ready();
        in.armRecord = arm(STALE_GEN);
        refused(in, EarlyRootPolicy.GENERATION_MISMATCH,
                "a job that outlived the authorisation it was scheduled with refuses:"
                        + " job id, namespace, version, ksud digest and fingerprint"
                        + " all still agree, so nothing else could have caught it");
        in = ready();
        in.callbackGeneration = "";
        refused(in, EarlyRootPolicy.GENERATION_MISSING,
                "a callback whose extras carry no generation refuses; it may be a job"
                        + " restored from a build that minted none");
        in = ready();
        in.callbackGeneration = null;
        refused(in, EarlyRootPolicy.GENERATION_MISSING,
                "and an unreadable extras bundle is the same refusal, not a skipped"
                        + " comparison");
        check(EarlyRootPolicy.parseArm(EarlyRootPolicy.formatArm(ARMED_BOOT,
                        EarlyRootPolicy.EXPECTED_JOB_ID, NS, 15_000L, 1, CODE, NAME,
                        KSUD, FP, 300_000L, 1759000000000L, "")) == null,
                "an arm record with a blank generation does not parse as an arming;"
                        + " a record that cannot name its operation is the ambiguity"
                        + " the token removes");
        check(EarlyRootPolicy.parseArm(
                        "state=" + EarlyRootPolicy.STATE_ARMED + "\n"
                        + "armed_boot_id=" + ARMED_BOOT + "\n"
                        + "job_id=" + EarlyRootPolicy.EXPECTED_JOB_ID + "\n"
                        + "namespace=" + NS + "\n"
                        + "minimum_latency_ms=15000\n"
                        + "schedule_result=1\n"
                        + "version_code=" + CODE + "\n"
                        + "version_name=" + NAME + "\n"
                        + "ksud_sha256=" + KSUD + "\n"
                        + "device_fingerprint=" + FP + "\n"
                        + "armed_elapsed_ms=300000\n"
                        + "armed_wallclock_ms=1759000000000\n") == null,
                "an arm record in the OLD format, with no generation key at all,"
                        + " refuses rather than being accepted on fields that do not"
                        + " identify the arming");
        in = ready();
        in.armRecord = arm(GEN);
        in.callbackGeneration = GEN;
        allowed(in, "the two halves of one arming agree and the run is permitted");

        // The window bounds the clock; it does not bound the boot. Without a
        // state of its own, a callback the scheduler restored at 43 s in a boot
        // that completed at 30 s passes every condition and is recorded as
        // evidence for an ordering it violated.
        in = ready();
        in.callbackElapsedMs = 43_000L;
        in.bootCompletedState = EarlyRootPolicy.BOOT_COMPLETED;
        refused(in, EarlyRootPolicy.BOOT_ALREADY_COMPLETED,
                "a callback inside the 120 s window but AFTER boot completion refuses:"
                        + " the late path is already proven and this one's whole"
                        + " purpose is the ordering");
        in = ready();
        in.callbackElapsedMs = 1_000L;
        in.bootCompletedState = EarlyRootPolicy.BOOT_COMPLETED;
        refused(in, EarlyRootPolicy.BOOT_ALREADY_COMPLETED,
                "and an early clock does not excuse it; the two facts are checked"
                        + " separately because they are separate facts");
        in = ready();
        in.bootCompletedState = EarlyBootProbePolicy.UNKNOWN;
        refused(in, EarlyRootPolicy.BOOT_STATE_UNKNOWN,
                "a boot state nobody could read refuses; an ordering claim with one"
                        + " end missing proves nothing");
        in = ready();
        in.bootCompletedState = null;
        refused(in, EarlyRootPolicy.BOOT_STATE_UNKNOWN,
                "an absent boot state refuses rather than reading as not-completed");
        in = ready();
        in.bootCompletedState = "0";
        refused(in, EarlyRootPolicy.BOOT_STATE_UNKNOWN,
                "a value outside the vocabulary refuses instead of being guessed at,"
                        + " even one that looks like the right answer");
        in = ready();
        in.bootCompletedState = EarlyRootPolicy.BOOT_NOT_COMPLETED;
        allowed(in, "an UNSET sys.boot_completed is the normal early state and must"
                + " read NOT_COMPLETED, never UNKNOWN: mapping unset to UNKNOWN would"
                + " refuse every genuine early run");
        check(!EarlyRootPolicy.BOOT_NOT_COMPLETED.equals(EarlyBootProbePolicy.UNKNOWN)
                        && !EarlyRootPolicy.BOOT_COMPLETED.equals(
                                EarlyBootProbePolicy.UNKNOWN),
                "the three boot states are three distinct values");
        check(EarlyRootPolicy.evaluateBeforeReadiness(
                        bootCompleted()).code.equals(
                                EarlyRootPolicy.BOOT_ALREADY_COMPLETED),
                "the cheap pre-readiness stage refuses a completed boot too, before"
                        + " paying for the AMS sweep");

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

        // --- early load is authorized only for one exact repaired DZIF pair --
        // The old DZIF pair panicked during KernelSU manager discovery.
        // The owner's new authorization names one exact firmware and daemon.
        in = ready();
        refused(in, EarlyRootPolicy.ARTEFACT_NOT_AUTHORIZED,
                "a cycle with nothing else wrong with it still refuses: no"
                        + " validated early load exists for this pair");
        check(!EarlyRootPolicy.earlyLoadAuthorized(FP, KSUD),
                "the ZZIC pair is not cleared for an early load");
        check(!EarlyRootPolicy.earlyLoadAuthorized(
                        "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/"
                                + "S938BXXUCDZIF_OXMCDZIF:user/release-keys",
                        "f680f959472e994110eb1281d6aa47ed3cd934ae5775f5e9e378a2e94"
                                + "6ae69e3"),
                "the exact DZIF pair whose early load panicked the kernel is not"
                        + " cleared");
        final String DZIF_FP = "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/"
                + "S938BXXUCDZIF_OXMCDZIF:user/release-keys";
        final String REPAIRED_KSUD =
                "3861dbd4e3b16f6edf5ac73601848522a055e62c3128be678e261d94547d32ee";
        check(EarlyRootPolicy.earlyLoadAuthorized(DZIF_FP, REPAIRED_KSUD),
                "the owner authorized this exact repaired DZIF pair for an early"
                        + " attempt, without claiming physical early acceptance");
        check(!EarlyRootPolicy.earlyLoadAuthorized(DZIF_FP, "b".repeat(64))
                        && !EarlyRootPolicy.earlyLoadAuthorized("other/firmware",
                                REPAIRED_KSUD),
                "neither a different daemon nor a different firmware inherits"
                        + " the owner authorization");
        in = ready();
        in.deviceFingerprint = DZIF_FP;
        in.ksudSha256 = REPAIRED_KSUD;
        in.armRecord = EarlyRootPolicy.formatArm(ARMED_BOOT,
                EarlyRootPolicy.EXPECTED_JOB_ID, NS, 15_000L, 1, CODE, NAME,
                REPAIRED_KSUD, DZIF_FP, 300_000L, 1759000000000L, GEN);
        in.qualificationRecord = AutoRootPolicy.formatQualification(CODE, NAME,
                REPAIRED_KSUD, DZIF_FP, QUAL_BOOT, 1759000000000L, false,
                QUAL_BOOT);
        check(EarlyRootPolicy.evaluate(in).allow,
                "an otherwise valid cycle with the authorized exact DZIF pair"
                        + " reaches the dispatch decision");
        check(!EarlyRootPolicy.earlyLoadAuthorized(null, KSUD)
                        && !EarlyRootPolicy.earlyLoadAuthorized(FP, null)
                        && !EarlyRootPolicy.earlyLoadAuthorized("", "")
                        && !EarlyRootPolicy.earlyLoadAuthorized(FP, ""),
                "a missing fingerprint or an unpinned daemon digest is not a"
                        + " cleared artefact; absence is never clearance");
        // Half a key is not a key: the pair is what was validated, so a daemon
        // carried to another firmware, or another daemon on this firmware, is a
        // different experiment.
        check(!EarlyRootPolicy.earlyLoadAuthorized(FP, "0".repeat(64))
                        && !EarlyRootPolicy.earlyLoadAuthorized("other/firmware", KSUD),
                "clearance is keyed on BOTH halves, so neither can speak for the"
                        + " other");
        // The suspension is about bytes, not about a boot, so nothing the device
        // happens to look like can lift it.
        in = ready();
        in.markerState = AutoRootPolicy.MARKER_ABSENT;
        in.liveSelinux = 1;
        in.readinessState = EarlyBootProbePolicy.NETWORKSTACK_READY;
        in.journalRecord = null;
        in.autoRootJournalRecord = null;
        refused(in, EarlyRootPolicy.ARTEFACT_NOT_AUTHORIZED,
                "a clean device does not authorize an unrelated artefact");

        // ------------------------------------------------------------------
        // The unresolved-incident latch (P0-D).
        //
        // The shape the incident report requires: a journal left at STARTED
        // with native_started=1, naming a boot that is not this one, next to an
        // unexplained reboot. Before this latch existed it was discarded as
        // "last boot's record" on the very next boot.
        // ------------------------------------------------------------------
        final String ACKNOWLEDGED_BOOT =
                "5a7c2537-9693-44f9-8b2e-e26a1b3a10f2";
        final String DEAD_BOOT = "11111111-aaaa-bbbb-cccc-222222222222";
        final String OTHER_KSUD = "b".repeat(64);

        EarlyRootPolicy.Incident acknowledged = EarlyRootPolicy.detectIncident(
                EarlyRootPolicy.formatJournal(ACKNOWLEDGED_BOOT,
                        AutoRootPolicy.PHASE_STARTED, 1, true),
                null, BOOT, BOOT, 0L);
        check(acknowledged != null && acknowledged.ksudSha256.isEmpty()
                        && EarlyRootPolicy.incidentAcknowledged(acknowledged)
                        && !EarlyRootPolicy.incidentBlocks(acknowledged,
                                REPAIRED_KSUD),
                "the examined historical boot is acknowledged even though its"
                        + " incident could not identify its daemon");
        EarlyRootPolicy.Inputs authorizedWithHistory = ready();
        authorizedWithHistory.deviceFingerprint = DZIF_FP;
        authorizedWithHistory.ksudSha256 = REPAIRED_KSUD;
        authorizedWithHistory.armRecord = EarlyRootPolicy.formatArm(ARMED_BOOT,
                EarlyRootPolicy.EXPECTED_JOB_ID, NS, 15_000L, 1, CODE, NAME,
                REPAIRED_KSUD, DZIF_FP, 300_000L, 1759000000000L, GEN);
        authorizedWithHistory.qualificationRecord =
                AutoRootPolicy.formatQualification(CODE, NAME, REPAIRED_KSUD,
                        DZIF_FP, QUAL_BOOT, 1759000000000L, false, QUAL_BOOT);
        authorizedWithHistory.incidentRecord =
                EarlyRootPolicy.formatIncident(acknowledged);
        authorizedWithHistory.journalRecord =
                EarlyRootPolicy.formatJournal(ACKNOWLEDGED_BOOT,
                        AutoRootPolicy.PHASE_STARTED, 1, true);
        check(EarlyRootPolicy.evaluate(authorizedWithHistory).allow,
                "the acknowledged historical record stays present while the"
                        + " exact authorized pair passes the full gate");

        // Detection: exactly one shape is an incident.
        check(EarlyRootPolicy.detectIncident(
                        EarlyRootPolicy.formatJournal(DEAD_BOOT,
                                AutoRootPolicy.PHASE_STARTED, 1, true),
                        arm(), BOOT, BOOT, 0L) != null,
                "STARTED with native_started=1 in a previous boot is an incident");
        check(EarlyRootPolicy.detectIncident(
                        EarlyRootPolicy.formatJournal(BOOT,
                                AutoRootPolicy.PHASE_STARTED, 1, true),
                        arm(), BOOT, BOOT, 0L) == null,
                "a journal naming THIS boot is the one-attempt question, not an"
                        + " incident");
        check(EarlyRootPolicy.detectIncident(
                        EarlyRootPolicy.formatJournal(DEAD_BOOT,
                                AutoRootPolicy.PHASE_PREFLIGHT, 1, false),
                        arm(), BOOT, BOOT, 0L) == null,
                "native_started=0 means transaction 5 never issued, so provably"
                        + " nothing was written");
        check(EarlyRootPolicy.detectIncident(
                        EarlyRootPolicy.formatJournal(DEAD_BOOT,
                                AutoRootPolicy.PHASE_COMPLETE, 1, true),
                        arm(), BOOT, BOOT, 0L) == null,
                "a boot that completed reported its result");
        check(EarlyRootPolicy.detectIncident(
                        EarlyRootPolicy.formatJournal(DEAD_BOOT,
                                AutoRootPolicy.PHASE_FAILED_LOCKED, 1, true),
                        arm(), BOOT, BOOT, 0L) == null,
                "a locked failure accounted for itself; an incident is a run that"
                        + " did not");
        check(EarlyRootPolicy.detectIncident(null, arm(), BOOT, BOOT, 0L) == null
                        && EarlyRootPolicy.detectIncident("", arm(), BOOT, BOOT, 0L) == null,
                "no journal is no incident");
        check(EarlyRootPolicy.detectIncident("phase=nonsense\n", arm(), BOOT,
                        BOOT, 0L) == null,
                "an unparsable journal is NOT reported as 'no incident' here: the"
                        + " caller already refuses on it, and answering would turn"
                        + " the strictest refusal in the file into a pass");

        // Attribution comes from the arm record, which is the same cycle's.
        EarlyRootPolicy.Incident attributed = EarlyRootPolicy.detectIncident(
                EarlyRootPolicy.formatJournal(DEAD_BOOT,
                        AutoRootPolicy.PHASE_STARTED, 1, true),
                arm(), BOOT, BOOT, 1759000000000L);
        check(attributed != null && KSUD.equals(attributed.ksudSha256)
                        && CODE == attributed.versionCode
                        && DEAD_BOOT.equals(attributed.bootId),
                "the incident is attributed to the artefact the arm record names");
        EarlyRootPolicy.Incident unattributed = EarlyRootPolicy.detectIncident(
                EarlyRootPolicy.formatJournal(DEAD_BOOT,
                        AutoRootPolicy.PHASE_STARTED, 1, true),
                null, BOOT, BOOT, 0L);
        check(unattributed != null && unattributed.ksudSha256.isEmpty(),
                "a missing arm record yields an UNATTRIBUTED incident, not no"
                        + " incident");
        check(!EarlyRootPolicy.incidentAcknowledged(attributed)
                        && !EarlyRootPolicy.incidentAcknowledged(unattributed)
                        && !EarlyRootPolicy.incidentAcknowledged(null),
                "a new boot, even with no artefact identity, cannot inherit the"
                        + " historical acknowledgement");

        // Applicability. The middle case is what keeps the latch usable.
        check(EarlyRootPolicy.incidentBlocks(attributed, KSUD),
                "an incident on this exact daemon digest refuses");
        check(!EarlyRootPolicy.incidentBlocks(attributed, OTHER_KSUD),
                "a corrected module is a new ksud digest, so the incident does not"
                        + " refuse a different artefact");
        check(EarlyRootPolicy.incidentBlocks(unattributed, KSUD)
                        && EarlyRootPolicy.incidentBlocks(unattributed, OTHER_KSUD),
                "an incident that could not be attributed refuses EVERY artefact;"
                        + " absence is never agreement");
        check(!EarlyRootPolicy.incidentBlocks(null, KSUD),
                "no incident refuses nothing");
        check(EarlyRootPolicy.incidentBlocks(attributed, null)
                        && EarlyRootPolicy.incidentBlocks(attributed, ""),
                "a dispatch that cannot name its own daemon digest cannot clear an"
                        + " incident either");

        // The record round-trips losslessly, including the unattributed case -
        // if UNKNOWN came back as a digest, incidentBlocks would compare against
        // it as if it were one.
        EarlyRootPolicy.Incident reparsed = EarlyRootPolicy.parseIncident(
                EarlyRootPolicy.formatIncident(attributed));
        check(reparsed != null && DEAD_BOOT.equals(reparsed.bootId)
                        && KSUD.equals(reparsed.ksudSha256)
                        && CODE == reparsed.versionCode
                        && reparsed.nativeStarted,
                "an attributed incident record round-trips");
        EarlyRootPolicy.Incident reparsedBlank = EarlyRootPolicy.parseIncident(
                EarlyRootPolicy.formatIncident(unattributed));
        check(reparsedBlank != null && reparsedBlank.ksudSha256.isEmpty()
                        && reparsedBlank.versionName.isEmpty()
                        && reparsedBlank.deviceFingerprint.isEmpty(),
                "an unattributed incident round-trips as blank, not as the literal"
                        + " UNKNOWN");

        // Strict parse: one element spoiled at a time.
        check(EarlyRootPolicy.parseIncident(null) == null
                        && EarlyRootPolicy.parseIncident("") == null
                        && EarlyRootPolicy.parseIncident(
                                AutoRootPolicy.RECORD_UNREADABLE) == null,
                "an absent or unreadable incident record does not parse");
        String good = EarlyRootPolicy.formatIncident(attributed);
        check(EarlyRootPolicy.parseIncident(
                        good.replace("native_started=1", "native_started=0")) == null,
                "an incident record claiming transaction 5 was never issued is not"
                        + " an incident record");
        check(EarlyRootPolicy.parseIncident(
                        good.replace("phase=" + AutoRootPolicy.PHASE_STARTED,
                                "phase=" + AutoRootPolicy.PHASE_COMPLETE)) == null,
                "an incident record naming a phase that reported does not parse");
        check(EarlyRootPolicy.parseIncident(good + "extra_key=1\n") == null
                        && EarlyRootPolicy.parseIncident(
                                good + "phase=" + AutoRootPolicy.PHASE_STARTED
                                        + "\n") == null
                        && EarlyRootPolicy.parseIncident(
                                good.replace("observed_wallclock_ms=1759000000000",
                                        "observed_wallclock_ms=soon")) == null
                        && EarlyRootPolicy.parseIncident(
                                good.replace("incident_boot_id=" + DEAD_BOOT + "\n",
                                        "")) == null,
                "an unknown key, a duplicate key, an unparsable number and a"
                        + " missing key each refuse");

        // And the gate itself, at the entry point, for each reading.
        in = ready();
        in.incidentRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in, EarlyRootPolicy.INCIDENT_UNREADABLE,
                "an unreadable incident record refuses; it may name an open one");
        in = ready();
        in.incidentRecord = "incident_boot_id=x\n";
        refused(in, EarlyRootPolicy.INCIDENT_MALFORMED,
                "an incident record this build cannot account for refuses");
        in = ready();
        in.incidentRecord = EarlyRootPolicy.formatIncident(attributed);
        refused(in, EarlyRootPolicy.INCIDENT_UNRESOLVED,
                "an open incident on this artefact refuses the dispatch");
        in = ready();
        in.incidentRecord = EarlyRootPolicy.formatIncident(unattributed);
        refused(in, EarlyRootPolicy.INCIDENT_UNRESOLVED,
                "an unattributable open incident refuses the dispatch");
        // A corrected artefact: the arm record, the dispatch and the
        // qualification all name the new digest, which is what actually happens
        // after a rebuild. Changing only in.ksudSha256 would refuse at
        // BUILD_MISMATCH first and prove nothing about the incident latch.
        in = ready();
        in.incidentRecord = EarlyRootPolicy.formatIncident(attributed);
        in.ksudSha256 = OTHER_KSUD;
        in.armRecord = EarlyRootPolicy.formatArm(ARMED_BOOT,
                EarlyRootPolicy.EXPECTED_JOB_ID, NS, 15_000L, 1, CODE, NAME,
                OTHER_KSUD, FP, 300_000L, 1759000000000L, GEN);
        in.qualificationRecord = AutoRootPolicy.formatQualification(CODE, NAME,
                OTHER_KSUD, FP, QUAL_BOOT, 1759000000000L, false, QUAL_BOOT);
        // Not `allowed` in the strict sense: a new digest is also not in the
        // (empty) authorisation allowlist, so the one remaining objection is
        // that one - which is exactly what allowed() asserts.
        allowed(in, "an incident attributed to the previous artefact is not a"
                + " corrected one's objection");
        in = ready();
        in.incidentRecord = null;
        in.journalRecord = EarlyRootPolicy.formatJournal(DEAD_BOOT,
                AutoRootPolicy.PHASE_STARTED, 1, true);
        refused(in, EarlyRootPolicy.INCIDENT_IN_JOURNAL,
                "a stale STARTED journal with no incident record refuses, and with"
                        + " its own code: the run that should have recorded it is"
                        + " the run that died");
        in = ready();
        in.incidentRecord = null;
        in.journalRecord = EarlyRootPolicy.formatJournal(DEAD_BOOT,
                AutoRootPolicy.PHASE_COMPLETE, 1, true);
        allowed(in, "a previous boot that COMPLETED is still last boot's record and"
                + " must not lock this one");

        // The latch is durable where the journal is not: archivePreviousCycle()
        // moves the journal aside, so a cycle later only the incident record
        // remembers. Both readings exist for that reason and this asserts the
        // second one does not depend on the first.
        in = ready();
        in.incidentRecord = EarlyRootPolicy.formatIncident(attributed);
        in.journalRecord = null;
        refused(in, EarlyRootPolicy.INCIDENT_UNRESOLVED,
                "the incident record refuses on its own, after the journal that"
                        + " produced it has been archived");

        // ------------------------------------------------------------------
        // The incident LOG, and the second-incident regression Codex found on
        // PR #55.
        //
        // The defect: with one record, incident A on the panicking artefact
        // occupied the only slot, and the arming's "A does not block B, return"
        // branch never looked at the journal. So corrected artefact B could die
        // after transaction 5, have its STARTED journal archived, and run again
        // with nothing remembering it.
        // ------------------------------------------------------------------
        final String DEAD_BOOT_B = "11111111-2222-3333-4444-555555555555";

        EarlyRootPolicy.Incident incidentA = attributed;          // names KSUD
        EarlyRootPolicy.Incident incidentB = EarlyRootPolicy.detectIncident(
                EarlyRootPolicy.formatJournal(DEAD_BOOT_B,
                        AutoRootPolicy.PHASE_STARTED, 1, true),
                EarlyRootPolicy.formatArm(ARMED_BOOT,
                        EarlyRootPolicy.EXPECTED_JOB_ID, NS, 15_000L, 1, CODE,
                        NAME, OTHER_KSUD, FP, 300_000L, 1759000000000L, GEN),
                BOOT, BOOT, 1759000001000L);
        check(incidentB != null && OTHER_KSUD.equals(incidentB.ksudSha256),
                "a second incident is attributed to the corrected artefact");

        String logA = EarlyRootPolicy.appendIncident(null, incidentA);
        String logAB = EarlyRootPolicy.appendIncident(logA, incidentB);

        java.util.List<EarlyRootPolicy.Incident> parsedA =
                EarlyRootPolicy.parseIncidents(logA);
        java.util.List<EarlyRootPolicy.Incident> parsedAB =
                EarlyRootPolicy.parseIncidents(logAB);
        check(parsedA != null && parsedA.size() == 1
                        && parsedAB != null && parsedAB.size() == 2
                        && DEAD_BOOT.equals(parsedAB.get(0).bootId)
                        && DEAD_BOOT_B.equals(parsedAB.get(1).bootId)
                        && KSUD.equals(parsedAB.get(0).ksudSha256)
                        && OTHER_KSUD.equals(parsedAB.get(1).ksudSha256),
                "the log holds both incidents, oldest first, each keeping its own"
                        + " attribution");
        check(EarlyRootPolicy.parseIncidents(null) != null
                        && EarlyRootPolicy.parseIncidents(null).isEmpty()
                        && EarlyRootPolicy.parseIncidents("").isEmpty(),
                "an absent log is an empty log, not a malformed one");
        check(EarlyRootPolicy.parseIncidents(
                        AutoRootPolicy.RECORD_UNREADABLE) == null,
                "an unreadable log does not parse");
        // One bad entry refuses the whole log: the entry this build cannot read
        // may be the one that would have blocked.
        check(EarlyRootPolicy.parseIncidents(
                        logA + "\n\nincident_boot_id=x\n") == null,
                "one unaccountable entry refuses the whole log rather than being"
                        + " skipped");

        // This is the regression itself: B's incident must refuse B.
        check(EarlyRootPolicy.blockingIncident(parsedA, OTHER_KSUD) == null,
                "with only A recorded, the corrected artefact B is not refused -"
                        + " which is what made the hole reachable");
        EarlyRootPolicy.Incident blocksB =
                EarlyRootPolicy.blockingIncident(parsedAB, OTHER_KSUD);
        check(blocksB != null && DEAD_BOOT_B.equals(blocksB.bootId),
                "once B's own incident is in the log it refuses B, and names B's"
                        + " boot rather than A's");
        EarlyRootPolicy.Incident blocksOriginal =
                EarlyRootPolicy.blockingIncident(parsedAB, KSUD);
        check(blocksOriginal != null && DEAD_BOOT.equals(blocksOriginal.bootId),
                "A still refuses the original artefact with B's entry beside it");
        check(EarlyRootPolicy.blockingIncident(parsedAB, "c".repeat(64)) == null,
                "a third, untried artefact is refused by neither");
        check(EarlyRootPolicy.blockingIncident(null, KSUD) == null,
                "a log that did not parse yields no blocking incident; the caller"
                        + " refuses on the parse instead");

        // Duplicate suppression, or every arming after a detection walks the
        // log to its bound.
        check(EarlyRootPolicy.incidentRecorded(parsedAB, incidentA)
                        && EarlyRootPolicy.incidentRecorded(parsedAB, incidentB),
                "an incident already in the log is recognised, by the boot it"
                        + " happened in");
        check(!EarlyRootPolicy.incidentRecorded(parsedA, incidentB),
                "an incident not yet in the log is not recognised");
        check(EarlyRootPolicy.incidentRecorded(parsedAB, unattributed),
                "an unattributed incident from the same boot as a recorded one is"
                        + " the same incident: the boot is what identifies it");

        // The bound, and that a full log refuses the append rather than growing.
        String fullLog = null;
        for (int i = 0; i < EarlyRootPolicy.MAX_INCIDENTS; i++) {
            EarlyRootPolicy.Incident one = EarlyRootPolicy.detectIncident(
                    EarlyRootPolicy.formatJournal("boot-" + i,
                            AutoRootPolicy.PHASE_STARTED, 1, true),
                    arm(), BOOT, BOOT, 0L);
            fullLog = EarlyRootPolicy.appendIncident(fullLog, one);
        }
        check(EarlyRootPolicy.parseIncidents(fullLog) != null
                        && EarlyRootPolicy.parseIncidents(fullLog).size()
                                == EarlyRootPolicy.MAX_INCIDENTS,
                "the log parses at exactly MAX_INCIDENTS entries");
        check(EarlyRootPolicy.incidentLogHasRoom(logAB)
                        && !EarlyRootPolicy.incidentLogHasRoom(fullLog),
                "a full log has no room; the append is refused rather than the"
                        + " bound exceeded");
        check(!EarlyRootPolicy.incidentLogHasRoom(
                        AutoRootPolicy.RECORD_UNREADABLE),
                "an unreadable log has no room either: it is not replaced");
        check(EarlyRootPolicy.incidentLogHasRoom(null),
                "an absent log has room");
        check(EarlyRootPolicy.parseIncidents(
                        EarlyRootPolicy.appendIncident(fullLog, incidentB)) == null,
                "a log one past the bound does not parse, so nothing downstream"
                        + " reads it as a shorter one");

        // And at the gate, with the log form.
        in = ready();
        in.incidentRecord = logAB;
        in.ksudSha256 = OTHER_KSUD;
        in.armRecord = EarlyRootPolicy.formatArm(ARMED_BOOT,
                EarlyRootPolicy.EXPECTED_JOB_ID, NS, 15_000L, 1, CODE, NAME,
                OTHER_KSUD, FP, 300_000L, 1759000000000L, GEN);
        in.qualificationRecord = AutoRootPolicy.formatQualification(CODE, NAME,
                OTHER_KSUD, FP, QUAL_BOOT, 1759000000000L, false, QUAL_BOOT);
        refused(in, EarlyRootPolicy.INCIDENT_UNRESOLVED,
                "the gate refuses the corrected artefact once its OWN unexplained"
                        + " death is in the log");
        in.incidentRecord = logA;
        allowed(in, "with only the previous artefact's incident recorded, the"
                + " corrected one is not refused by the latch");
        in = ready();
        in.incidentRecord = logA + "\n\nincident_boot_id=x\n";
        refused(in, EarlyRootPolicy.INCIDENT_MALFORMED,
                "one unaccountable entry refuses at the gate too");

        // ------------------------------------------------------------------
        // A journal the arming cannot account for must refuse BEFORE the
        // archive, under both log conditions.
        //
        // detectIncident() answers null for an unreadable and for a malformed
        // journal, and null means "no pending incident" downstream. So without
        // a refusal of its own the arming walked past a journal that may say
        // STARTED with native_started=1, archivePreviousCycle() moved it to
        // .prev, and the gate's JOURNAL_UNREADABLE / JOURNAL_MALFORMED
        // verdicts became unreachable for anything older than the current
        // cycle. Reported on PR #55.
        //
        // The policy half is asserted here; that the ARMING refuses on it is a
        // Kotlin path, guarded statically in tools/profile_binding_audit.py.
        // ------------------------------------------------------------------
        final String MALFORMED_JOURNAL = "boot_id=" + DEAD_BOOT + "\nphase=who\n";
        check(EarlyRootPolicy.parseJournal(MALFORMED_JOURNAL) == null,
                "the fixture really is a journal this build cannot account for");
        check(EarlyRootPolicy.detectIncident(
                        AutoRootPolicy.RECORD_UNREADABLE, arm(), BOOT, BOOT, 0L) == null
                        && EarlyRootPolicy.detectIncident(
                                MALFORMED_JOURNAL, arm(), BOOT, BOOT, 0L) == null,
                "detectIncident answers null for an unreadable and a malformed"
                        + " journal alike - which is why the caller about to destroy"
                        + " the evidence has to refuse on them itself");

        // (a) empty incident log
        in = ready();
        in.incidentRecord = null;
        in.journalRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in, EarlyRootPolicy.JOURNAL_UNREADABLE,
                "an unreadable journal refuses with an empty incident log");
        in = ready();
        in.incidentRecord = null;
        in.journalRecord = MALFORMED_JOURNAL;
        refused(in, EarlyRootPolicy.JOURNAL_MALFORMED,
                "a malformed journal refuses with an empty incident log");

        // (b) a nonblocking prior incident A beside a new digest B - the branch
        // that used to return early and skip the journal entirely.
        EarlyRootPolicy.Inputs correctedB = ready();
        correctedB.ksudSha256 = OTHER_KSUD;
        correctedB.armRecord = EarlyRootPolicy.formatArm(ARMED_BOOT,
                EarlyRootPolicy.EXPECTED_JOB_ID, NS, 15_000L, 1, CODE, NAME,
                OTHER_KSUD, FP, 300_000L, 1759000000000L, GEN);
        correctedB.qualificationRecord = AutoRootPolicy.formatQualification(CODE,
                NAME, OTHER_KSUD, FP, QUAL_BOOT, 1759000000000L, false, QUAL_BOOT);
        correctedB.incidentRecord = logA;

        in = correctedB;
        in.journalRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in, EarlyRootPolicy.JOURNAL_UNREADABLE,
                "an unreadable journal refuses even when the recorded incident is"
                        + " attributed to another artefact");
        in.journalRecord = MALFORMED_JOURNAL;
        refused(in, EarlyRootPolicy.JOURNAL_MALFORMED,
                "a malformed journal refuses even when the recorded incident is"
                        + " attributed to another artefact");
        // And the control: the same inputs with a readable, accountable journal
        // from a boot that completed are not refused by any of this.
        in.journalRecord = EarlyRootPolicy.formatJournal(DEAD_BOOT,
                AutoRootPolicy.PHASE_COMPLETE, 1, true);
        allowed(in, "a readable journal from a boot that reported is not refused by"
                + " the unaccountable-journal checks");

        // --- the trigger and the role are named, never defaulted -----------
        // Two triggers reach this policy and they do not carry the same
        // evidence; the two roles read the cycle record in opposite directions.
        // A caller that does not say gets the refusing answer.
        EarlyRootPolicy.Inputs in2 = ready();
        in2.trigger = null;
        refused(in2, EarlyRootPolicy.TRIGGER_UNRECOGNISED,
                "a dispatch that names no trigger refuses");
        in2.trigger = "expedited-job";
        refused(in2, EarlyRootPolicy.TRIGGER_UNRECOGNISED,
                "a trigger this policy has no evidence model for refuses");
        in2 = ready();
        in2.role = null;
        refused(in2, EarlyRootPolicy.ROLE_UNRECOGNISED,
                "a caller that does not say which side of the dispatch it is"
                        + " refuses");
        in2.role = "whatever";
        refused(in2, EarlyRootPolicy.ROLE_UNRECOGNISED,
                "an unrecognised role refuses rather than taking the permissive"
                        + " reading");
        in2 = ready();
        in2.trigger = EarlyRootPolicy.TRIGGER_LOCKED_BOOT;
        allowed(in2, "the deterministic LOCKED_BOOT_COMPLETED trigger is weighed by"
                + " the same gate as the job callback");

        // --- the boot animation is its own element -------------------------
        // The fact the product requirement is stated in, and the one the 120 s
        // window was standing in for. On 2026-10-13 the callback arrived with
        // bootanim_exit=1 AND sys.boot_completed=1; these are separate facts and
        // either one alone must refuse.
        in2 = ready();
        in2.bootanimState = EarlyRootPolicy.BOOTANIM_EXITED;
        refused(in2, EarlyRootPolicy.BOOTANIM_ALREADY_EXITED,
                "a run after the boot animation left the screen refuses even while"
                        + " sys.boot_completed is still unset");
        in2.bootanimState = EarlyBootProbePolicy.UNKNOWN;
        refused(in2, EarlyRootPolicy.BOOTANIM_STATE_UNKNOWN,
                "an unreadable service.bootanim.exit refuses; a reading nobody took"
                        + " is not an animation still on screen");
        in2.bootanimState = null;
        refused(in2, EarlyRootPolicy.BOOTANIM_STATE_UNKNOWN,
                "an absent boot-animation reading refuses");
        in2.bootanimState = "0";
        refused(in2, EarlyRootPolicy.BOOTANIM_STATE_UNKNOWN,
                "the raw property value is not one of the three states and refuses;"
                        + " the mapping belongs in EarlyRootEnv");
        in2 = ready();
        in2.bootCompletedState = EarlyRootPolicy.BOOT_NOT_COMPLETED;
        in2.bootanimState = EarlyRootPolicy.BOOTANIM_RUNNING;
        allowed(in2, "inside the animation and before boot completion is the early"
                + " window");

        // --- the cycle record: one arming, one boot, one claimed run --------
        // What the scheduler used to provide by consuming the job, and what
        // nothing provides for a broadcast that arrives in every boot.
        String cycleBound = boundCycle();
        EarlyRootPolicy.Cycle cycle = EarlyRootPolicy.parseCycle(cycleBound);
        check(cycle != null && EarlyRootPolicy.CYCLE_BOUND.equals(cycle.state)
                        && cycle.generation.equals(GEN) && cycle.runBootId.equals(BOOT)
                        && !cycle.claimed() && cycle.claimElapsedMs == -1L,
                "a bound cycle record parses and reports itself unclaimed");
        EarlyRootPolicy.Cycle claimedParsed = EarlyRootPolicy.parseCycle(
                claimedCycle(EarlyRootPolicy.TRIGGER_LOCKED_BOOT, BOOT));
        check(claimedParsed != null && claimedParsed.claimed()
                        && EarlyRootPolicy.TRIGGER_LOCKED_BOOT.equals(
                                claimedParsed.trigger),
                "a claimed cycle record names the trigger that claimed it");
        check(EarlyRootPolicy.parseCycle(cycleBound + "unknown=1\n") == null,
                "an unknown cycle key refuses");
        check(EarlyRootPolicy.parseCycle(
                        cycleBound.replace("run_boot_id=" + BOOT + "\n", "")) == null,
                "a missing cycle key refuses");
        check(EarlyRootPolicy.parseCycle(cycleBound.replace(
                        "state=" + EarlyRootPolicy.CYCLE_BOUND, "state=WHATEVER"))
                        == null,
                "an unrecognised cycle state refuses");
        check(EarlyRootPolicy.parseCycle(cycleBound.replace(
                        "trigger=" + EarlyRootPolicy.TRIGGER_NONE,
                        "trigger=" + EarlyRootPolicy.TRIGGER_JOB)) == null,
                "a BOUND cycle that names a claiming trigger refuses: nothing has"
                        + " claimed it, so the field would be a claim nobody made");
        check(EarlyRootPolicy.parseCycle(claimedCycle(
                        EarlyRootPolicy.TRIGGER_NONE, BOOT)) == null,
                "a CLAIMED cycle that names no trigger refuses: the trigger is the"
                        + " only field that says which path reached the chain");
        check(EarlyRootPolicy.parseCycle(claimedCycle(
                        EarlyRootPolicy.TRIGGER_JOB, BOOT)
                        .replace("claim_elapsed_ms=15400", "claim_elapsed_ms=-1"))
                        == null,
                "a CLAIMED cycle with no claim timestamp refuses; it orders nothing");
        check(EarlyRootPolicy.parseCycle(
                        cycleBound.replace("claim_elapsed_ms=-1",
                                "claim_elapsed_ms=15400")) == null,
                "a BOUND cycle carrying a claim timestamp refuses");
        check(EarlyRootPolicy.parseCycle(AutoRootPolicy.RECORD_UNREADABLE) == null,
                "an unreadable cycle record does not parse as a cycle");

        in2 = ready();
        in2.cycleRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in2, EarlyRootPolicy.CYCLE_UNREADABLE,
                "an unreadable cycle record refuses: it may say this arming was"
                        + " already claimed");
        in2.cycleRecord = "state=nonsense\n";
        refused(in2, EarlyRootPolicy.CYCLE_MALFORMED,
                "a cycle record this build cannot account for refuses");
        in2.cycleRecord = EarlyRootPolicy.formatCycle(EarlyRootPolicy.CYCLE_BOUND,
                STALE_GEN, BOOT, EarlyRootPolicy.TRIGGER_NONE, 15_100L, -1L);
        refused(in2, EarlyRootPolicy.CYCLE_FOREIGN,
                "a cycle belonging to another arming refuses rather than being"
                        + " treated as absent; the arming archives it or refuses");
        in2.cycleRecord = claimedCycle(EarlyRootPolicy.TRIGGER_JOB, BOOT);
        refused(in2, EarlyRootPolicy.ARM_ALREADY_CLAIMED,
                "a trigger finding this arming already claimed in this boot refuses:"
                        + " one arming, one run, whichever trigger got there first");
        in2.cycleRecord = claimedCycle(EarlyRootPolicy.TRIGGER_LOCKED_BOOT, DEAD_BOOT);
        refused(in2, EarlyRootPolicy.ARM_ALREADY_CLAIMED,
                "an arming claimed in an EARLIER boot stays claimed; the arm record"
                        + " outliving its cycle is exactly what this record fixes");
        in2.cycleRecord = EarlyRootPolicy.formatCycle(EarlyRootPolicy.CYCLE_BOUND,
                GEN, DEAD_BOOT, EarlyRootPolicy.TRIGGER_NONE, 15_100L, -1L);
        refused(in2, EarlyRootPolicy.ARM_EXPIRED,
                "an arming bound to a boot that has passed refuses: a broadcast"
                        + " arrives in every boot, and one arming is for one boot");
        in2.cycleRecord = cycleBound;
        allowed(in2, "an arming bound to THIS boot and not yet claimed is still"
                + " live for the second trigger of the same boot");

        // --- the claimed run's side of the same record ----------------------
        // The service's authorisation is a claim of its own, not merely a gate
        // that passes. Anything sharing our uid can call startService.
        EarlyRootPolicy.Inputs run = claimedRun();
        allowed(run, "a service whose claim names this arming and this boot is"
                + " authorised");
        run = claimedRun();
        run.cycleRecord = null;
        refused(run, EarlyRootPolicy.CLAIM_MISSING,
                "a service started with no claim on disk refuses: a run nothing"
                        + " claimed is a run no trigger authorised");
        run = claimedRun();
        run.cycleRecord = boundCycle();
        refused(run, EarlyRootPolicy.CLAIM_MISSING,
                "a BOUND cycle is not a claim; the service still refuses");
        run = claimedRun();
        run.cycleRecord = claimedCycle(EarlyRootPolicy.TRIGGER_JOB, DEAD_BOOT);
        refused(run, EarlyRootPolicy.CLAIM_NOT_THIS_BOOT,
                "a claim from an earlier boot cannot authorise a service restarted"
                        + " into this one");
        run = claimedRun();
        run.callbackGeneration = STALE_GEN;
        /*
         * Transitively, and earlier: the relayed token is compared to the arm
         * record (GENERATION_MISMATCH) and the cycle is compared to the arm
         * record (CYCLE_FOREIGN), so a relayed token that is not the claimed
         * arming's cannot reach the claim check. This case exists to prove the
         * composition holds, so that nobody adds a third comparison that no
         * input can reach.
         */
        refused(run, EarlyRootPolicy.GENERATION_MISMATCH,
                "a relayed generation that is not the claimed arming's refuses"
                        + " before the claim is read at all");
        run = claimedRun();
        run.cycleRecord = EarlyRootPolicy.formatCycle(EarlyRootPolicy.CYCLE_CLAIMED,
                STALE_GEN, BOOT, EarlyRootPolicy.TRIGGER_JOB, 15_100L, 15_400L);
        refused(run, EarlyRootPolicy.CYCLE_FOREIGN,
                "a claim naming another arming refuses for the claimed run too");

        // --- the arming is consumed BEFORE any transient refusal -----------
        // Codex caught this on PR #61 and the finding was correct: the
        // dispatcher bound the cycle only after the clock, the window, the boot
        // state and the animation had all passed, so a boot that arrived a
        // second too late left the arm record live and the NEXT boot's
        // LOCKED_BOOT_COMPLETED ran unarmed. These cases are the contract that
        // keeps the two halves apart, and they are the reason the split is a
        // function rather than a comment.
        EarlyRootPolicy.Inputs t = ready();
        t.callbackElapsedMs = 521_707L;
        refused(t, EarlyRootPolicy.PAST_WINDOW, "the run-2 callback still refuses");
        binds(t, "...and the arming is still bound to that boot, so a later boot"
                + " cannot inherit it");
        t = ready();
        t.bootCompletedState = EarlyRootPolicy.BOOT_COMPLETED;
        refused(t, EarlyRootPolicy.BOOT_ALREADY_COMPLETED,
                "a boot that already completed refuses");
        binds(t, "...and still consumes the arming");
        t = ready();
        t.bootanimState = EarlyRootPolicy.BOOTANIM_EXITED;
        refused(t, EarlyRootPolicy.BOOTANIM_ALREADY_EXITED,
                "a boot whose animation already exited refuses");
        binds(t, "...and still consumes the arming: arriving a second too late"
                + " must not leave the arming live for the next boot");
        t = ready();
        t.bootanimState = EarlyBootProbePolicy.UNKNOWN;
        binds(t, "an unreadable animation state refuses the run and still consumes"
                + " the arming");
        t = ready();
        t.callbackElapsedMs = -1L;
        refused(t, EarlyRootPolicy.CLOCK_UNAVAILABLE, "an unreadable clock refuses");
        binds(t, "...and still consumes the arming");
        t = ready();
        t.autoRootJournalRecord = EarlyRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_FAILED_LOCKED, 1, true);
        refused(t, EarlyRootPolicy.AUTO_BOOT_SPENT,
                "Auto Root having reached transaction 5 in this boot refuses");
        binds(t, "...and still consumes the arming");
        t = ready();
        t.journalRecord = EarlyRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_PREFLIGHT, 1, false);
        refused(t, EarlyRootPolicy.BOOT_SPENT,
                "a second entry in this boot refuses");
        binds(t, "...and still consumes the arming");

        // And the other direction: everything that refuses the same way in
        // EVERY boot belongs in the immutable half, where it must NOT consume
        // the owner's arming - a later boot reaches the same answer anyway.
        t = ready();
        t.armRecord = null;
        refusedBinding(t, EarlyRootPolicy.ARM_NO_RECORD,
                "an unarmed device never binds anything");
        t = ready();
        t.versionCode = CODE + 1;
        refusedBinding(t, EarlyRootPolicy.BUILD_MISMATCH,
                "an app update between the arming and the boot does not consume"
                        + " the arming");
        t = ready();
        t.qualificationRecord = null;
        refusedBinding(t, EarlyRootPolicy.NOT_QUALIFIED,
                "an unqualified build does not consume the arming");
        t = ready();
        t.cycleRecord = claimedCycle(EarlyRootPolicy.TRIGGER_JOB, BOOT);
        refusedBinding(t, EarlyRootPolicy.ARM_ALREADY_CLAIMED,
                "an arming already claimed refuses in the immutable half, so the"
                        + " second trigger of a boot never rewrites the claim");
        t = ready();
        t.cycleRecord = EarlyRootPolicy.formatCycle(EarlyRootPolicy.CYCLE_BOUND,
                GEN, DEAD_BOOT, EarlyRootPolicy.TRIGGER_NONE, 15_100L, -1L);
        refusedBinding(t, EarlyRootPolicy.ARM_EXPIRED,
                "an arming bound to a boot that has passed refuses in the"
                        + " immutable half");
        t = ready();
        t.incidentRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refusedBinding(t, EarlyRootPolicy.INCIDENT_UNREADABLE,
                "an unreadable incident log refuses in the immutable half: it"
                        + " refuses every boot alike, so it must not spend an arming");
        t = ready();
        t.trigger = null;
        refusedBinding(t, EarlyRootPolicy.TRIGGER_UNRECOGNISED,
                "a dispatch that names no trigger binds nothing");
        t = ready();
        binds(t, "a clean early window binds, which is what the dispatcher does"
                + " before it weighs anything transient");

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
