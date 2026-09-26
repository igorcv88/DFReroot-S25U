import com.polygraphene.df.reroot.AutoRootPolicy;

/**
 * Host regression suite for the Auto Root scheduling policy.
 *
 * Every case here is one the device cannot be asked to reproduce on demand: a
 * soft reboot that keeps boot_id, a journal from a run that died after the
 * page-cache writes, a qualification recorded against another ksud. The policy
 * is pure precisely so these stay testable, and a gate that cannot fail is not a
 * gate - so each element gets its own negative case.
 */
public class AutoRootPolicyTest {

    private static int pass = 0;
    private static int fail = 0;

    private static final int CODE = 8;
    private static final String NAME = "2.0.5-zzic";
    private static final String KSUD =
            "14fb9eaf14cb6dc0a32aace6024e89124bba1ea8b4b37979136b7c2017dec97a";
    private static final String FP =
            "samsung/zzic/pa3q:17/BP4A.250505.005/S938BXXUCZZIC:user/release-keys";
    private static final String QUAL_BOOT = "0643a5e2-9a44-4bb9-b7a4-31a3b255e3ac";
    private static final String BOOT = "11111111-2222-3333-4444-555555555555";

    /** Armed in the boot that qualified it, which is the normal shape. */
    private static String qualified(boolean optIn) {
        return qualified(optIn, QUAL_BOOT);
    }

    private static String qualified(boolean optIn, String armedInBoot) {
        return AutoRootPolicy.formatQualification(CODE, NAME, KSUD, FP, QUAL_BOOT,
                1759000000000L, optIn, armedInBoot);
    }

    /** A preflight whose every element is satisfied; each test spoils exactly one. */
    private static AutoRootPolicy.Inputs ready() {
        AutoRootPolicy.Inputs in = new AutoRootPolicy.Inputs();
        in.qualificationRecord = qualified(true);
        in.journalRecord = null;
        in.currentBootId = BOOT;
        in.deviceFingerprint = FP;
        in.ksudSha256 = KSUD;
        in.versionName = NAME;
        in.versionCode = CODE;
        in.bootCompleted = true;
        in.markerState = AutoRootPolicy.MARKER_ABSENT;
        in.liveSelinux = 1;
        in.networkStack = AutoRootPolicy.PROCESS_PRESENT;
        return in;
    }

    private static void check(boolean ok, String what) {
        if (ok) {
            pass++;
            System.out.println("  ok   - " + what);
        } else {
            fail++;
            System.out.println("  FAIL - " + what);
        }
    }

    private static void allowed(AutoRootPolicy.Inputs in, String what) {
        AutoRootPolicy.Decision d = AutoRootPolicy.evaluate(in);
        check(d.allow, what + " (reason=" + d.reason + ")");
    }

    private static void refused(AutoRootPolicy.Inputs in, String what) {
        AutoRootPolicy.Decision d = AutoRootPolicy.evaluate(in);
        check(!d.allow && !d.retryable, what + " (reason=" + d.reason + ")");
    }

    private static void retryable(AutoRootPolicy.Inputs in, String what) {
        AutoRootPolicy.Decision d = AutoRootPolicy.evaluate(in);
        check(!d.allow && d.retryable, what + " (reason=" + d.reason + ")");
    }

    public static void main(String[] args) {
        System.out.println("[T] AutoRootPolicy");

        allowed(ready(), "a fully satisfied preflight allows exactly one attempt");

        // --- qualification and opt-in --------------------------------------
        AutoRootPolicy.Inputs in = ready();
        in.qualificationRecord = null;
        refused(in, "no qualification record at all is refused");

        in = ready();
        in.qualificationRecord = "";
        refused(in, "an empty qualification record is refused");

        in = ready();
        in.qualificationRecord = qualified(false);
        refused(in, "qualified but not opted in is refused");

        in = ready();
        in.qualificationRecord = qualified(true).replace("state=QUALIFIED", "state=PENDING");
        refused(in, "a qualification in any other state is refused");

        in = ready();
        in.qualificationRecord = qualified(true).replace("opt_in=1\n", "");
        refused(in, "a qualification missing a field is refused, not read as a subset");

        in = ready();
        in.qualificationRecord = qualified(true) + "opt_in=1\n";
        refused(in, "a duplicated key is refused");

        in = ready();
        in.qualificationRecord = qualified(true) + "auto_root=yes\n";
        refused(in, "an unknown key is refused");

        in = ready();
        in.qualificationRecord = qualified(true) + "garbage\n";
        refused(in, "a malformed line is refused");

        // --- the qualification must belong to THIS build and firmware -------
        in = ready();
        in.versionCode = CODE + 1;
        refused(in, "another versionCode invalidates the qualification");

        in = ready();
        in.versionName = "2.0.6-zzic";
        refused(in, "another versionName invalidates the qualification");

        in = ready();
        in.ksudSha256 = "b82c194db398ace90fa777bed4d8419c70041eb99d7bbe2915caa900100de75f";
        refused(in, "another ksud digest invalidates the qualification");

        in = ready();
        in.deviceFingerprint = FP.replace("ZZIC", "ZZI4");
        refused(in, "another firmware fingerprint invalidates the qualification");

        // --- full boot vs soft reboot --------------------------------------
        in = ready();
        in.currentBootId = null;
        refused(in, "an unavailable boot_id is refused");

        in = ready();
        in.currentBootId = "   ";
        refused(in, "a blank boot_id is refused");

        in = ready();
        in.currentBootId = QUAL_BOOT;
        refused(in, "the boot that qualified Auto Root does not run it (soft reboot keeps"
                + " boot_id, so a framework restart triggers nothing)");

        /*
         * The hole this closes: armed in a boot that had already finished booting,
         * so nothing was journalled, and the qualifying boot was an earlier one. A
         * framework restart re-delivers BOOT_COMPLETED with the SAME boot_id, and
         * every other condition passed. The switch is now bound to its boot.
         */
        in = ready();
        in.qualificationRecord = qualified(true, BOOT);
        in.journalRecord = null;
        refused(in, "a boot in which Auto Root was switched on does not run it, even with"
                + " no journal entry and a different qualifying boot");

        in = ready();
        in.qualificationRecord = qualified(true, "99999999-0000-0000-0000-000000000000");
        allowed(in, "armed in some earlier boot, this boot may run");

        // --- one attempt per boot ------------------------------------------
        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT, AutoRootPolicy.PHASE_STARTED,
                1, true);
        refused(in, "a STARTED journal for this boot blocks any further attempt");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT, AutoRootPolicy.PHASE_COMPLETE,
                1, true);
        refused(in, "a COMPLETE journal for this boot blocks a second run");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_FAILED_LOCKED, 1, true);
        refused(in, "a locked boot stays locked until a hard reboot");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT, "PREFLIGHT", 1, true)
                .replace("native_started=1", "native_started=1");
        refused(in, "native_started=1 locks the boot whatever the phase says");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT, "PREFLIGHT",
                AutoRootPolicy.MAX_ATTEMPTS_PER_BOOT, false);
        refused(in, "exhausted readiness attempts stop the loop for this boot");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT, "PREFLIGHT",
                AutoRootPolicy.MAX_ATTEMPTS_PER_BOOT - 1, false);
        allowed(in, "a pre-STARTED attempt below the cap may still run");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(QUAL_BOOT,
                AutoRootPolicy.PHASE_FAILED_LOCKED, 3, true);
        allowed(in, "last boot's locked journal does not lock this boot");

        in = ready();
        in.journalRecord = "phase=STARTED\n";
        refused(in, "a malformed journal refuses the boot rather than being ignored");

        // An I/O error on an existing journal must not read as "no journal": the
        // record it could not read may say STARTED, i.e. the chain already wrote.
        in = ready();
        in.journalRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in, "an unreadable journal refuses the boot, never counts as absent");

        in = ready();
        in.qualificationRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refused(in, "an unreadable qualification refuses and says why");

        // A journal that parses but carries a state this build does not know is
        // uncertain evidence about a boot that may already have run the chain.
        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT, "UNKNOWN", 0, false);
        refused(in, "an unknown journal phase refuses instead of falling through");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT, "", 0, false);
        refused(in, "an empty journal phase refuses");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_PREFLIGHT, 0, false)
                .replace("native_started=0", "native_started=2");
        refused(in, "a native_started value other than 0 or 1 refuses");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT,
                AutoRootPolicy.PHASE_PREFLIGHT, 0, false);
        allowed(in, "a known PREFLIGHT phase with no attempt spent still runs");

        in = ready();
        in.journalRecord = AutoRootPolicy.formatJournal(BOOT, "PREFLIGHT", 0, false)
                .replace("attempts=0", "attempts=many");
        refused(in, "a non-numeric attempt count is refused");

        // --- observed device state ----------------------------------------
        in = ready();
        in.markerState = AutoRootPolicy.MARKER_PRESENT;
        refused(in, "/dev/df or any dfm marker refuses an automatic attempt");

        // A probe that could not answer is not an answer. This is the same rule
        // the native has_mark() already follows by returning -1.
        in = ready();
        in.markerState = AutoRootPolicy.MARKER_UNKNOWN;
        refused(in, "an undeterminable marker probe refuses, never reads as absent");

        in = new AutoRootPolicy.Inputs();
        in.qualificationRecord = qualified(true);
        in.currentBootId = BOOT;
        in.deviceFingerprint = FP;
        in.ksudSha256 = KSUD;
        in.versionName = NAME;
        in.versionCode = CODE;
        in.bootCompleted = true;
        in.liveSelinux = 1;
        in.networkStack = AutoRootPolicy.PROCESS_PRESENT;
        refused(in, "an unset marker field defaults to UNKNOWN and refuses");

        in = ready();
        in.liveSelinux = 0;
        refused(in, "starting from Permissive is refused");

        in = ready();
        in.liveSelinux = -1;
        refused(in, "an unreadable SELinux state is refused, not assumed enforcing");

        in = ready();
        in.bootCompleted = false;
        retryable(in, "sys.boot_completed=0 is retryable, not a refusal");

        in = ready();
        in.networkStack = AutoRootPolicy.PROCESS_ABSENT;
        retryable(in, "an absent NetworkStack process is retryable");

        in = ready();
        in.networkStack = AutoRootPolicy.PROCESS_UNKNOWN;
        AutoRootPolicy.Decision d = AutoRootPolicy.evaluate(in);
        check(d.allow && d.reason.contains("NETWORKSTACK_PROCESS_FOUND=UNKNOWN"),
                "an undeterminable NetworkStack probe proceeds but says so explicitly"
                        + " (the hop's PROCESS_LOOKUP is the authority)");

        // A permanent refusal must never be reported as retryable: that is how a
        // bounded loop becomes an unbounded one.
        in = ready();
        in.bootCompleted = false;
        in.qualificationRecord = null;
        refused(in, "a permanent refusal wins over a retryable readiness failure");

        // --- qualification of a finished run -------------------------------
        check(AutoRootPolicy.qualifies(0, true, 1),
                "a verified manual completion qualifies");
        check(!AutoRootPolicy.qualifies(0, false, 1),
                "native result 0 without POST_ROOT_COMPLETE does not qualify");
        check(!AutoRootPolicy.qualifies(0, true, 0),
                "completion with SELinux 0 does not qualify");
        check(!AutoRootPolicy.qualifies(1, true, 1),
                "a failed native result does not qualify");

        // --- opt-in toggling cannot invent a qualification -----------------
        check(AutoRootPolicy.withOptIn(null, true, BOOT) == null,
                "opting in with no qualification record yields nothing");
        check(AutoRootPolicy.withOptIn(AutoRootPolicy.RECORD_UNREADABLE, true, BOOT) == null,
                "opting in on an unreadable record yields nothing");
        check(AutoRootPolicy.withOptIn(qualified(false), true, null) == null,
                "opting in without a boot id yields nothing; the switch must be bound"
                        + " to the boot it was flipped in");
        check(!AutoRootPolicy.isOptedIn(AutoRootPolicy.RECORD_UNREADABLE, CODE, NAME, KSUD, FP)
                        && !AutoRootPolicy.isQualified(AutoRootPolicy.RECORD_UNREADABLE,
                                CODE, NAME, KSUD, FP),
                "an unreadable record is neither qualified nor opted in");
        check(AutoRootPolicy.withOptIn("state=QUALIFIED\n", true, BOOT) == null,
                "opting in on a malformed record yields nothing");
        String flipped = AutoRootPolicy.withOptIn(qualified(false), true, BOOT);
        check(flipped != null && AutoRootPolicy.isOptedIn(flipped, CODE, NAME, KSUD, FP),
                "opting in on a valid record preserves it and sets the flag");
        String off = AutoRootPolicy.withOptIn(flipped, false, BOOT);
        check(off != null && !AutoRootPolicy.isOptedIn(off, CODE, NAME, KSUD, FP)
                        && AutoRootPolicy.isQualified(off, CODE, NAME, KSUD, FP),
                "opting back out keeps the qualification and clears only the flag");
        check(!AutoRootPolicy.isOptedIn(qualified(true), CODE + 1, NAME, KSUD, FP),
                "isOptedIn is false for another build");
        AutoRootPolicy.Inputs armedNow = ready();
        armedNow.qualificationRecord = flipped;
        armedNow.journalRecord = null;
        AutoRootPolicy.Decision armedDecision = AutoRootPolicy.evaluate(armedNow);
        check(!armedDecision.allow && armedDecision.reason.contains("switched on during this boot"),
                "the record written by opting in refuses in that same boot");

        check(AutoRootPolicy.MAX_ATTEMPTS_PER_BOOT >= 8,
                "the readiness poll cap leaves room for a slow boot instead of"
                        + " closing the window in the first minute");

        System.out.println("");
        System.out.println("AutoRootPolicyTest: " + pass + "/" + (pass + fail) + " passed");
        if (fail != 0) System.exit(1);
    }
}
