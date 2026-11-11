import com.polygraphene.df.installer.SuAuthorization;
import com.polygraphene.df.installer.SuAuthorization.Verdict;

/**
 * Host regression suite for DFInstaller's root-authorization reading.
 *
 * The installer used to decide it had root with
 * {@code rootOut.contains("uid=0")} over a string that already concatenated
 * stdout, stderr and {@code [rc=N]}. The permissive cases below are the ones
 * that matters: output that merely mentions uid=0 must not enable a privileged
 * button, and a non-zero exit status must not be ignored.
 *
 * None of these states can be produced on demand on a device. A refusal needs
 * an unauthorized package, a non-zero uid needs a half-granted shell, and an
 * unintelligible answer needs a broken su. That is why the classifier is pure
 * and this suite exists.
 *
 *   javac -d out installer/src/main/java/com/polygraphene/df/installer/SuAuthorization.java \
 *         tools/tests/SuAuthorizationTest.java && java -cp out SuAuthorizationTest
 *
 * See tools/tests/run_installer_tests.sh.
 */
public class SuAuthorizationTest {

    // ---------------------------------------------------------------- harness
    static int total = 0;
    static int failed = 0;

    static void check(boolean cond, String fmt, Object... args) {
        total++;
        String msg = String.format(fmt, args);
        if (cond) {
            System.out.println("  ok   - " + msg);
        } else {
            failed++;
            System.out.println("  FAIL - " + msg);
        }
    }

    static SuAuthorization.Result ok(String stdout) {
        return SuAuthorization.classify(false, 0, stdout, "");
    }

    static void expect(SuAuthorization.Result r, Verdict verdict, boolean rooted,
                       String what) {
        check(r.verdict() == verdict, "%s -> %s (got %s)", what, verdict,
                r.verdict());
        check(r.rooted() == rooted, "%s -> rooted=%s", what, rooted);
    }

    // ------------------------------------------------------------- the grant
    static void testRealIdOutputIsAccepted() {
        System.out.println("real id(1) output on a granted shell");
        // Verbatim shape of `id` under KernelSU's su on this firmware.
        SuAuthorization.Result r = ok(
                "uid=0(root) gid=0(root) groups=0(root) "
                + "context=u:r:su:s0\n");
        expect(r, Verdict.ROOT_OK, true, "uid=0(root) line");
        check(r.uid() == 0, "uid is read as 0");
        check(r.detail().contains("uid 0 confirmed"), "detail names the grant");
    }

    static void testTrailingWhitespaceAndCrlfStillParse() {
        System.out.println("whitespace and CRLF around the uid field");
        expect(ok("  uid=0(root) gid=0(root)\r\n"), Verdict.ROOT_OK, true,
                "indented CRLF line");
        expect(ok("uid=0 gid=0\n"), Verdict.ROOT_OK, true,
                "uid field ended by a space");
    }

    static void testUidFieldOnALaterLineIsFound() {
        System.out.println("uid field after a banner line");
        expect(ok("su: switching\nuid=0(root) gid=0(root)\n"),
                Verdict.ROOT_OK, true, "second line carries the field");
    }

    // ------------------------------------------------------- the refusals
    static void testExecFailureIsAbsence() {
        System.out.println("su could not be executed at all");
        SuAuthorization.Result r = SuAuthorization.classify(true, 0, "", "");
        expect(r, Verdict.SU_ABSENT, false, "exec failed");
        check(r.detail().contains("obtain temporary root"),
                "absence still points at obtaining temporary root");
    }

    static void testNonZeroExitIsDenialEvenWithUidZeroPrinted() {
        System.out.println("su exits non-zero while printing uid=0");
        // The exact shape the old substring test accepted: a refusal whose
        // text contains the token. The exit status is the authority here.
        SuAuthorization.Result r = SuAuthorization.classify(
                false, 1, "uid=0(root) gid=0(root)\n", "su: access denied\n");
        expect(r, Verdict.SU_DENIED, false, "rc=1 with uid=0 in stdout");
        check(r.detail().contains("access denied"),
                "the denial's own message is surfaced");
        check(r.detail().contains("authorized out of band"),
                "managerless authorization is named as the action");
    }

    static void testDenialQuotingUidZeroOnStderrIsNotAPass() {
        System.out.println("denial on stderr that mentions uid=0");
        SuAuthorization.Result r = SuAuthorization.classify(
                false, 13, "", "su: uid=0 not permitted for this package\n");
        expect(r, Verdict.SU_DENIED, false, "rc=13, uid=0 only on stderr");
    }

    static void testUidZeroOnStderrOfASuccessfulRunIsNotAPass() {
        System.out.println("rc=0 but the uid field only appears on stderr");
        // stderr is excluded deliberately: it is attacker- and
        // diagnostic-shaped text, not id(1)'s answer.
        SuAuthorization.Result r = SuAuthorization.classify(
                false, 0, "", "warning: uid=0(root)\n");
        expect(r, Verdict.SU_UNINTELLIGIBLE, false, "field only on stderr");
    }

    static void testProseMentioningUidZeroIsNotAPass() {
        System.out.println("prose containing uid=0 mid-line");
        expect(ok("this shell would be uid=0(root) if authorized\n"),
                Verdict.SU_UNINTELLIGIBLE, false, "field not at line start");
    }

    static void testWrongIdentityIsRefusedAndNamed() {
        System.out.println("su granted something other than uid 0");
        SuAuthorization.Result r = ok("uid=2000(shell) gid=2000(shell)\n");
        expect(r, Verdict.SU_WRONG_IDENTITY, false, "uid=2000");
        check(r.uid() == 2000, "the observed uid is reported, not discarded");
        check(r.detail().contains("2000"), "detail names the uid it got");
    }

    static void testSystemUidIsNotRoot() {
        System.out.println("uid 1000 is not a substitute for uid 0");
        // The invariant the whole project rests on: android.uid.system is not
        // root, and nothing may treat it as root.
        expect(ok("uid=1000(system) gid=1000(system)\n"),
                Verdict.SU_WRONG_IDENTITY, false, "uid=1000");
    }

    static void testEmptyAndMalformedOutputAreRefused() {
        System.out.println("empty and malformed successful output");
        expect(ok(""), Verdict.SU_UNINTELLIGIBLE, false, "empty stdout");
        expect(SuAuthorization.classify(false, 0, null, null),
                Verdict.SU_UNINTELLIGIBLE, false, "null stdout");
        expect(ok("uid=\n"), Verdict.SU_UNINTELLIGIBLE, false,
                "uid= with no digits");
        expect(ok("uid=root\n"), Verdict.SU_UNINTELLIGIBLE, false,
                "uid= with a name instead of digits");
        expect(ok("uid=0x0(root)\n"), Verdict.SU_UNINTELLIGIBLE, false,
                "hex uid is not parsed as 0");
    }

    static void testUidPrefixIsNotAUidField() {
        System.out.println("a longer token starting with the uid digits");
        // "uid=01(...)" is uid 1, and "uid=0abc" is not a uid at all. Neither
        // may be read as uid 0 by a prefix match.
        expect(ok("uid=0abc gid=0\n"), Verdict.SU_UNINTELLIGIBLE, false,
                "uid=0abc");
        SuAuthorization.Result r = ok("uid=01(daemon) gid=01\n");
        expect(r, Verdict.SU_WRONG_IDENTITY, false, "uid=01 is uid 1");
        check(r.uid() == 1, "uid=01 reads as 1, not 0");
    }

    static void testOversizedUidIsNotRoundedIntoRoot() {
        System.out.println("a uid too large for int");
        expect(ok("uid=99999999999999(weird) gid=0\n"),
                Verdict.SU_UNINTELLIGIBLE, false, "overflowing uid");
    }

    static void testNegativeExitCodeIsStillADenial() {
        System.out.println("su killed by a signal");
        expect(SuAuthorization.classify(false, -9, "uid=0(root)\n", ""),
                Verdict.SU_DENIED, false, "rc=-9");
    }

    // ---------------------------------------------------- the only passing door
    static void testExactlyOneVerdictPermitsAnything() {
        System.out.println("only ROOT_OK permits anything");
        for (Verdict v : Verdict.values()) {
            if (v == Verdict.ROOT_OK) {
                continue;
            }
            // Drive each verdict through classify() rather than constructing a
            // Result, so the mapping under test is the real one.
            SuAuthorization.Result r;
            switch (v) {
                case SU_ABSENT:
                    r = SuAuthorization.classify(true, 0, "", "");
                    break;
                case SU_DENIED:
                    r = SuAuthorization.classify(false, 1, "", "");
                    break;
                case SU_WRONG_IDENTITY:
                    r = ok("uid=2000(shell)\n");
                    break;
                case SU_UNINTELLIGIBLE:
                    r = ok("nothing useful\n");
                    break;
                default:
                    throw new AssertionError("unhandled verdict " + v);
            }
            check(r.verdict() == v, "%s is reachable from classify()", v);
            check(!r.rooted(), "%s does not permit anything", v);
        }
    }

    static void testEveryDetailIsBoundaryTagged() {
        System.out.println("every detail line is tagged for the log");
        SuAuthorization.Result[] all = {
            SuAuthorization.classify(true, 0, "", ""),
            SuAuthorization.classify(false, 1, "", ""),
            ok("uid=2000(shell)\n"),
            ok("nothing useful\n"),
            ok("uid=0(root)\n"),
        };
        for (SuAuthorization.Result r : all) {
            check(r.detail().startsWith("[DFR][su] "),
                    "%s detail is tagged", r.verdict());
        }
    }

    public static void main(String[] args) {
        System.out.println("DFInstaller su-authorization regression suite\n");
        testRealIdOutputIsAccepted();
        testTrailingWhitespaceAndCrlfStillParse();
        testUidFieldOnALaterLineIsFound();
        testExecFailureIsAbsence();
        testNonZeroExitIsDenialEvenWithUidZeroPrinted();
        testDenialQuotingUidZeroOnStderrIsNotAPass();
        testUidZeroOnStderrOfASuccessfulRunIsNotAPass();
        testProseMentioningUidZeroIsNotAPass();
        testWrongIdentityIsRefusedAndNamed();
        testSystemUidIsNotRoot();
        testEmptyAndMalformedOutputAreRefused();
        testUidPrefixIsNotAUidField();
        testOversizedUidIsNotRoundedIntoRoot();
        testNegativeExitCodeIsStillADenial();
        testExactlyOneVerdictPermitsAnything();
        testEveryDetailIsBoundaryTagged();
        System.out.printf("%n%d/%d checks passed, %d failed%n",
                total - failed, total, failed);
        System.exit(failed == 0 ? 0 : 1);
    }
}
