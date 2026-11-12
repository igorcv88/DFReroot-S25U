import com.polygraphene.df.companion.AttestationReport;
import com.polygraphene.df.companion.CallerAuthorization;
import com.polygraphene.df.companion.CompanionContract;
import com.polygraphene.df.companion.RmgIdentity;

/**
 * The companion's two decisions, with one negative case per element.
 *
 * None of these is reachable on a device without arranging a state nobody can
 * arrange: a caller signed by another key, a shared uid without DFReroot in it,
 * a package manager that will not answer, a root shell that returns a truncated
 * report or another call's nonce. So they are exercised here or nowhere
 * (AGENTS.md 5).
 */
public final class CompanionContractTest {
    private static int checks;

    private static void expect(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }

    private static final String OURS =
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    private static final String THEIRS =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    private static final String NONCE = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    private static final String[] SYSTEM_UID_PACKAGES = {
            "android", "com.android.settings", "com.polygraphene.df.reroot",
    };

    private static CallerAuthorization.Verdict caller(
            int uid, String[] packages, String client, String own, int version) {
        return CallerAuthorization.evaluate(uid, packages, client, own, version);
    }

    private static String report(String... overrides) {
        StringBuilder s = new StringBuilder();
        s.append("DFRC_UID=0\n");
        s.append("DFRC_SELINUX=Enforcing\n");
        s.append("DFRC_NONCE=").append(NONCE).append('\n');
        s.append("DFRC_KSUD_SHA256_PRE=").append(RmgIdentity.RMG_KSUD_SHA256).append('\n');
        s.append("DFRC_KSUD_SIZE=").append(RmgIdentity.RMG_KSUD_SIZE).append('\n');
        s.append("DFRC_STATUS=package=com.polygraphene.df.companion user=0 uid=10600"
                + " profile=present root=true persistence=not-checked\n");
        s.append("DFRC_STATUS_RC=0\n");
        s.append("DFRC_KSUD_SHA256_POST=").append(RmgIdentity.RMG_KSUD_SHA256).append('\n');
        s.append("DFRC_MODULES=kernelsu\n");
        s.append("DFRC_END=1\n");
        String text = s.toString();
        for (int i = 0; i + 1 < overrides.length; i += 2) {
            text = text.replace(overrides[i], overrides[i + 1]);
        }
        return text;
    }

    public static void main(String[] args) {
        // --- caller authorization ------------------------------------------
        CallerAuthorization.Verdict ok =
                caller(1000, SYSTEM_UID_PACKAGES, OURS, OURS, 1);
        expect(ok.allowed, "the platform uid carrying DFReroot with our key is allowed");
        expect(ok.reason.contains("not distinguishable"),
                "the verdict states what a shared uid cannot establish");

        expect(!caller(10600, SYSTEM_UID_PACKAGES, OURS, OURS, 1).allowed,
                "an app uid is refused even with the right packages and key");
        expect(!caller(0, SYSTEM_UID_PACKAGES, OURS, OURS, 1).allowed,
                "uid 0 is refused: the client is uid 1000, not root");
        expect(!caller(1000, null, OURS, OURS, 1).allowed,
                "a package lookup that did not answer is refused, not assumed");
        expect(caller(1000, null, OURS, OURS, 1).reason.contains("not an identity"),
                "and the refusal says the lookup failed rather than naming the uid");
        expect(!caller(1000, new String[0], OURS, OURS, 1).allowed,
                "an empty package list is refused");
        expect(!caller(1000, new String[]{"android"}, OURS, OURS, 1).allowed,
                "a shared uid without DFReroot in it is refused");
        expect(!caller(1000, SYSTEM_UID_PACKAGES, THEIRS, OURS, 1).allowed,
                "a client signed by another certificate is refused");
        expect(!caller(1000, SYSTEM_UID_PACKAGES, null, OURS, 1).allowed,
                "an unavailable client digest is refused");
        expect(!caller(1000, SYSTEM_UID_PACKAGES, OURS, null, 1).allowed,
                "an unavailable own digest is refused");
        expect(!caller(1000, SYSTEM_UID_PACKAGES, "deadbeef", OURS, 1).allowed,
                "a malformed digest is refused");
        expect(!caller(1000, SYSTEM_UID_PACKAGES, OURS.replace('a', 'z'), OURS, 1).allowed,
                "a non-hex digest is refused");
        expect(caller(1000, SYSTEM_UID_PACKAGES, OURS.toUpperCase(), OURS, 1).allowed,
                "digest comparison is case-insensitive, as the platform's case varies");
        expect(!caller(1000, SYSTEM_UID_PACKAGES, OURS, OURS, 0).allowed,
                "contract version 0 is refused");
        expect(!caller(1000, SYSTEM_UID_PACKAGES, OURS, OURS, 2).allowed,
                "a future contract version is refused rather than interpreted");
        expect(caller(1000, SYSTEM_UID_PACKAGES, OURS, OURS, 2).rc
                        == CompanionContract.RC_VERSION_MISMATCH,
                "and a version skew is its own result code");

        // --- the attestation ------------------------------------------------
        AttestationReport.Verdict full = AttestationReport.evaluate(report(), NONCE);
        expect(full.attestation == AttestationReport.ATTEST_RMG_CONTRACT,
                "pinned daemon plus contract round-trip attests the RMG pair");
        expect(full.rootProven && full.ksudPinned && full.contractRoundTrip
                        && full.selinuxEnforcing && full.moduleNamed,
                "and every signal is reported separately");
        expect(full.signals().contains("ATTESTATION=RMG_CONTRACT"),
                "the signal line names the attestation level");

        expect(AttestationReport.evaluate(report(), "another-nonce").attestation
                        == AttestationReport.ATTEST_NONE,
                "a report that does not echo this call's nonce attests nothing");
        expect(AttestationReport.evaluate(report(), null).attestation
                        == AttestationReport.ATTEST_NONE,
                "no nonce means nothing binds the output to this call");
        expect(AttestationReport.evaluate(report("DFRC_END=1\n", ""), NONCE).attestation
                        == AttestationReport.ATTEST_NONE,
                "a truncated report is not a partial pass");
        expect(AttestationReport.evaluate(null, NONCE).attestation
                        == AttestationReport.ATTEST_NONE,
                "no output attests nothing");
        expect(AttestationReport.evaluate("", NONCE).attestation
                        == AttestationReport.ATTEST_NONE,
                "empty output attests nothing");
        expect(AttestationReport.evaluate(report() + report(), NONCE).attestation
                        == AttestationReport.ATTEST_NONE,
                "two concatenated reports are refused, not merged");

        // uid 0 and the root-only read are what prove privilege
        expect(AttestationReport.evaluate(report("DFRC_UID=0", "DFRC_UID=10600"), NONCE)
                        .attestation == AttestationReport.ATTEST_NONE,
                "a non-zero uid proves no root operation");
        AttestationReport.Verdict noRead = AttestationReport.evaluate(
                report("DFRC_KSUD_SHA256_PRE=" + RmgIdentity.RMG_KSUD_SHA256,
                        "DFRC_KSUD_SHA256_PRE="), NONCE);
        expect(noRead.attestation == AttestationReport.ATTEST_NONE,
                "without the root-only read nothing is proven");
        expect(!noRead.ksudPinned, "and the daemon is not reported as pinned");

        // the two halves, each alone
        AttestationReport.Verdict foreignKsud = AttestationReport.evaluate(
                report(RmgIdentity.RMG_KSUD_SHA256, THEIRS), NONCE);
        expect(foreignKsud.attestation == AttestationReport.ATTEST_ROOT_OPERATIONAL,
                "a foreign daemon with a working contract probe is operational only");
        expect(!foreignKsud.ksudPinned && foreignKsud.contractRoundTrip,
                "and the two halves are reported separately");
        expect(AttestationReport.evaluate(report("DFRC_STATUS_RC=0", "DFRC_STATUS_RC=1"),
                        NONCE).attestation == AttestationReport.ATTEST_ROOT_OPERATIONAL,
                "a failed contract probe leaves the module unattested");
        expect(AttestationReport.evaluate(
                        report("DFRC_STATUS=package=", "DFRC_STATUS=error: "), NONCE)
                        .attestation == AttestationReport.ATTEST_ROOT_OPERATIONAL,
                "an unparsable status line leaves the module unattested");
        expect(AttestationReport.evaluate(
                        report("DFRC_KSUD_SIZE=" + RmgIdentity.RMG_KSUD_SIZE,
                                "DFRC_KSUD_SIZE=1"), NONCE)
                        .attestation == AttestationReport.ATTEST_ROOT_OPERATIONAL,
                "a size that does not match the pin leaves the daemon unpinned");
        expect(AttestationReport.evaluate(
                        report("DFRC_KSUD_SIZE=" + RmgIdentity.RMG_KSUD_SIZE,
                                "DFRC_KSUD_SIZE=x"), NONCE)
                        .attestation == AttestationReport.ATTEST_ROOT_OPERATIONAL,
                "an unparsable size is not a matching one");

        // the post-invocation digest is what catches a replacement
        AttestationReport.Verdict swapped = AttestationReport.evaluate(
                report("DFRC_KSUD_SHA256_POST=" + RmgIdentity.RMG_KSUD_SHA256,
                        "DFRC_KSUD_SHA256_POST=" + THEIRS), NONCE);
        expect(swapped.attestation == AttestationReport.ATTEST_ROOT_OPERATIONAL,
                "a daemon replaced during the call is not attested");
        expect(!swapped.ksudPinned,
                "the second digest exists precisely to make that fail");

        // SELinux and the module name are observations, never the attestation
        expect(AttestationReport.evaluate(
                        report("DFRC_SELINUX=Enforcing", "DFRC_SELINUX=Permissive"), NONCE)
                        .attestation == AttestationReport.ATTEST_RMG_CONTRACT,
                "SELinux state is reported, not folded into the attestation");
        expect(!AttestationReport.evaluate(
                        report("DFRC_SELINUX=Enforcing", "DFRC_SELINUX=Permissive"), NONCE)
                        .selinuxEnforcing,
                "but it is reported truthfully for the caller to act on");
        expect(AttestationReport.evaluate(
                        report("DFRC_MODULES=kernelsu", "DFRC_MODULES=absent"), NONCE)
                        .attestation == AttestationReport.ATTEST_RMG_CONTRACT,
                "a module name adds nothing to an attestation built on the ioctl");

        System.out.println("CompanionContractTest: " + checks + "/" + checks + " passed");
    }
}
