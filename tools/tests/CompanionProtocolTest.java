import com.polygraphene.df.reroot.CompanionProtocol;

/**
 * The client's parser, with one negative per element.
 *
 * The important cases are not the malformed ones - they are the SHAPED ones: a
 * provider whose summary says RMG_CONTRACT while its own signals say otherwise,
 * and a level this build does not know. Believing either is how one string
 * would come to decide whether DFReroot thinks a foreign provider owns the
 * kernel.
 */
public final class CompanionProtocolTest {
    private static int checks;

    private static void expect(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }

    /** The exact line the companion produced on the device, 2026-11-12. */
    private static final String PHYSICAL =
            "ATTESTATION=RMG_CONTRACT ROOT_OPERATION=PASS KSUD_PINNED=PASS"
            + " CONTRACT_V1_ROUNDTRIP=PASS SELINUX_ENFORCING=PASS MODULE_NAMED=PASS";

    private static CompanionProtocol.Verdict parse(String s) {
        return CompanionProtocol.parseSignals(s);
    }

    public static void main(String[] args) {
        // --- the line a real device produced ------------------------------
        CompanionProtocol.Verdict ok = parse(PHYSICAL);
        expect(ok.rmgContract, "the physically captured line re-derives as RMG_CONTRACT");
        expect(ok.rootOperation && ok.ksudPinned && ok.contractRoundTrip
                        && ok.selinuxEnforcing && ok.moduleNamed,
                "and every signal is reported separately");

        // --- the summary is never taken at its word ------------------------
        expect(!parse(PHYSICAL.replace("KSUD_PINNED=PASS", "KSUD_PINNED=FAIL")).rmgContract,
                "a claimed RMG_CONTRACT with an unpinned daemon is refused");
        expect(parse(PHYSICAL.replace("KSUD_PINNED=PASS", "KSUD_PINNED=FAIL"))
                        .reason.contains("disagrees"),
                "and the refusal says the summary contradicts its own signals");
        expect(!parse(PHYSICAL.replace("CONTRACT_V1_ROUNDTRIP=PASS",
                        "CONTRACT_V1_ROUNDTRIP=FAIL")).rmgContract,
                "a claimed RMG_CONTRACT without the contract round-trip is refused");
        expect(!parse(PHYSICAL.replace("ROOT_OPERATION=PASS", "ROOT_OPERATION=FAIL")).rmgContract,
                "a claimed RMG_CONTRACT without a proven root operation is refused");
        expect(!parse(PHYSICAL.replace("ATTESTATION=RMG_CONTRACT",
                        "ATTESTATION=ROOT_OPERATIONAL")).rmgContract,
                "components that would support RMG but a lower claimed level is refused:"
                        + " the two must agree in both directions");

        // --- unknown and missing levels -------------------------------------
        expect(!parse(PHYSICAL.replace("ATTESTATION=RMG_CONTRACT",
                        "ATTESTATION=TOTALLY_FINE")).rmgContract,
                "an unrecognised attestation level is refused, never believed");
        expect(parse(PHYSICAL.replace("ATTESTATION=RMG_CONTRACT", "ATTESTATION=TOTALLY_FINE"))
                        .reason.contains("unrecognised"),
                "and the reason names it");
        expect(!parse("ROOT_OPERATION=PASS KSUD_PINNED=PASS CONTRACT_V1_ROUNDTRIP=PASS")
                        .rmgContract,
                "signals with no level at all are refused");

        // --- the honest lower level ----------------------------------------
        CompanionProtocol.Verdict operational = parse(
                "ATTESTATION=ROOT_OPERATIONAL ROOT_OPERATION=PASS KSUD_PINNED=FAIL"
                + " CONTRACT_V1_ROUNDTRIP=PASS SELINUX_ENFORCING=PASS MODULE_NAMED=PASS");
        expect(!operational.rmgContract, "ROOT_OPERATIONAL is not an RMG attestation");
        expect(operational.rootOperation && operational.contractRoundTrip
                        && !operational.ksudPinned,
                "and its component signals survive for the reader");

        CompanionProtocol.Verdict none = parse(
                "ATTESTATION=NONE ROOT_OPERATION=FAIL KSUD_PINNED=FAIL"
                + " CONTRACT_V1_ROUNDTRIP=FAIL SELINUX_ENFORCING=FAIL MODULE_NAMED=FAIL");
        expect(!none.rmgContract, "NONE attests nothing");

        // --- SELinux is reported, never folded into the attestation --------
        CompanionProtocol.Verdict permissive =
                parse(PHYSICAL.replace("SELINUX_ENFORCING=PASS", "SELINUX_ENFORCING=FAIL"));
        expect(permissive.rmgContract,
                "SELinux does not change what the provider attested about the module");
        expect(!permissive.selinuxEnforcing,
                "but it is reported truthfully, for RootEnvironment to refuse on");

        // --- malformed, absent and duplicated -------------------------------
        expect(!parse(null).rmgContract, "null signals attest nothing");
        expect(!parse("").rmgContract, "empty signals attest nothing");
        expect(!parse("   ").rmgContract, "blank signals attest nothing");
        expect(!parse(PHYSICAL + " ATTESTATION=NONE").rmgContract,
                "a duplicated key refuses the whole line rather than picking one");
        expect(parse(PHYSICAL + " ATTESTATION=NONE").reason.contains("duplicate"),
                "and says so");
        expect(parse(PHYSICAL + " SOMETHING_NEW=PASS").rmgContract,
                "an unknown EXTRA signal does not break a client that predates it");
        expect(parse(PHYSICAL + " bare_token").rmgContract,
                "a non key=value token is ignored, not fatal");
        expect(!parse("ATTESTATION=").rmgContract,
                "an empty level value is refused");
        expect(!parse(PHYSICAL.replace("ROOT_OPERATION=PASS", "ROOT_OPERATION=pass"))
                        .rmgContract,
                "signal values are compared exactly: 'pass' is not 'PASS'");
        expect(!parse(PHYSICAL.replace("ROOT_OPERATION=PASS", "ROOT_OPERATION=TRUE"))
                        .rmgContract,
                "an unrecognised signal value is FAIL, not a pass");

        // --- the client's own result codes stay out of the companion's range
        expect(CompanionProtocol.RC_CLIENT_NO_PROVIDER > CompanionProtocol.RC_ATTESTATION_INCONCLUSIVE
                        && CompanionProtocol.RC_CLIENT_MAIN_THREAD
                        > CompanionProtocol.RC_ATTESTATION_INCONCLUSIVE,
                "client-side codes cannot be confused with the provider's");

        System.out.println("CompanionProtocolTest: " + checks + "/" + checks + " passed");
    }
}
