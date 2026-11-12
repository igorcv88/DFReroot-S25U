package com.polygraphene.df.reroot;

import java.util.HashMap;
import java.util.Map;

/**
 * The client half of the companion contract: constants, and a parser that
 * RE-DERIVES the verdict instead of believing the provider's summary.
 *
 * <h2>Why these constants are a second copy</h2>
 *
 * The companion is a separate application module with its own
 * {@code applicationId}, and AGP cannot make one application module depend on
 * another, so the wire constants exist twice. That is the same shape as
 * {@code target_profile.c} and {@code zzic_profile.json} (AGENTS.md §3.10), and
 * it gets the same treatment: {@code tools/profile_binding_audit.py} parses
 * both files and fails on any divergence. A drift here would not be a compile
 * error - it would be a transaction the companion refuses at run time, on a
 * device, with "the transaction did not carry this interface's token" as the
 * only clue.
 *
 * <h2>Why the summary is not taken at its word</h2>
 *
 * The companion reports {@code ATTESTATION=RMG_CONTRACT} alongside the
 * component signals it derived that from. This parser recomputes the level from
 * the components and refuses when the two disagree. It costs nothing, and the
 * alternative is that one string decides whether DFReroot believes a foreign
 * provider owns the kernel - a claim whose evidence is right there in the same
 * message and can simply be checked. A provider whose summary contradicts its
 * own evidence is exactly the thing not to trust.
 */
public final class CompanionProtocol {

    private CompanionProtocol() {}

    // --- mirrored from companion/.../CompanionContract.java ------------------
    public static final String PACKAGE = "com.polygraphene.df.companion";
    public static final String ACTION = "com.polygraphene.df.companion.ROOT_OPERATIONS";
    public static final String PERMISSION =
            "com.polygraphene.df.companion.permission.ROOT_OPERATIONS";
    public static final String DESCRIPTOR = "com.polygraphene.df.companion.ICompanion";
    public static final int CONTRACT_VERSION = 1;
    public static final int TX_DESCRIBE = 1;
    public static final int TX_ATTEST = 2;
    public static final int RC_OK = 0;
    public static final int RC_CALLER_REFUSED = 1;
    public static final int RC_VERSION_MISMATCH = 2;
    public static final int RC_NO_ROOT = 3;
    public static final int RC_TIMEOUT = 4;
    public static final int RC_UNAVAILABLE = 5;
    public static final int RC_UNKNOWN_TRANSACTION = 6;
    public static final int RC_ATTESTATION_INCONCLUSIVE = 7;

    // --- client-side result codes, deliberately outside the companion's range -
    /** The companion is not installed, or its service could not be bound. */
    public static final int RC_CLIENT_NO_PROVIDER = 101;
    /** The installed companion is not signed by this app's certificate. */
    public static final int RC_CLIENT_FOREIGN_PROVIDER = 102;
    /** The reply was absent, truncated or unparsable. */
    public static final int RC_CLIENT_BAD_REPLY = 103;
    /**
     * The call was attempted on the main thread and refused there.
     *
     * Every component of this app runs inside {@code system_server}, and this
     * transaction waits on a bind and then on a root shell. Blocking that
     * looper is not a slow UI, it is a watchdog-visible stall of the system
     * process, so it is refused rather than merely discouraged.
     */
    public static final int RC_CLIENT_MAIN_THREAD = 104;

    // --- the signal keys the companion emits --------------------------------
    public static final String KEY_ATTESTATION = "ATTESTATION";
    public static final String KEY_ROOT_OPERATION = "ROOT_OPERATION";
    public static final String KEY_KSUD_PINNED = "KSUD_PINNED";
    public static final String KEY_CONTRACT_ROUNDTRIP = "CONTRACT_V1_ROUNDTRIP";
    public static final String KEY_SELINUX = "SELINUX_ENFORCING";
    public static final String KEY_MODULE_NAMED = "MODULE_NAMED";

    public static final String ATTEST_NONE = "NONE";
    public static final String ATTEST_ROOT_OPERATIONAL = "ROOT_OPERATIONAL";
    public static final String ATTEST_RMG_CONTRACT = "RMG_CONTRACT";

    /**
     * Deadline for the ATTEST transaction, enforced by {@link BoundedCall}.
     *
     * Outside the companion's own 20 s bound on its {@code su} child, so a
     * normal slow path completes and only a wedged handler trips this.
     *
     * It was declared and never read - the client called
     * {@code binder.transact(..., 0)}, which has no timeout at all, while this
     * constant made the call look bounded. The owner's review of PR C found it.
     * The audit now fails if it stops being referenced where it is enforced.
     */
    public static final long ATTEST_TIMEOUT_MS = 30_000L;
    /**
     * Deadline for DESCRIBE, which takes no root and reads nothing.
     *
     * Short on purpose: its job is the version handshake, so a remote that
     * cannot answer THAT within five seconds is not one to then ask for an
     * attestation.
     */
    public static final long DESCRIBE_TIMEOUT_MS = 5_000L;
    /** Deadline for the bind alone. */
    public static final long BIND_TIMEOUT_MS = 5_000L;

    /** Every signal separately, plus the level this side re-derived. */
    public static final class Verdict {
        /** True only when every element the RMG claim rests on is PASS. */
        public final boolean rmgContract;
        public final boolean rootOperation;
        public final boolean ksudPinned;
        public final boolean contractRoundTrip;
        public final boolean selinuxEnforcing;
        public final boolean moduleNamed;
        public final String reason;

        private Verdict(boolean rmgContract, boolean rootOperation, boolean ksudPinned,
                boolean contractRoundTrip, boolean selinuxEnforcing, boolean moduleNamed,
                String reason) {
            this.rmgContract = rmgContract;
            this.rootOperation = rootOperation;
            this.ksudPinned = ksudPinned;
            this.contractRoundTrip = contractRoundTrip;
            this.selinuxEnforcing = selinuxEnforcing;
            this.moduleNamed = moduleNamed;
            this.reason = reason;
        }
    }

    private static Verdict refuse(String reason) {
        return new Verdict(false, false, false, false, false, false, reason);
    }

    private static boolean pass(Map<String, String> v, String key) {
        return "PASS".equals(v.get(key));
    }

    /**
     * Parse one {@code signals()} line from the companion.
     *
     * Fail-closed at every step: an absent key is FAIL for that signal, an
     * unrecognised value is FAIL, a duplicate key refuses the whole line, and a
     * summary that disagrees with its own components refuses the whole line.
     */
    public static Verdict parseSignals(String signals) {
        if (signals == null || signals.trim().isEmpty()) {
            return refuse("the provider returned no signals");
        }
        Map<String, String> values = new HashMap<>();
        for (String token : signals.trim().split("\\s+")) {
            int eq = token.indexOf('=');
            if (eq <= 0 || eq == token.length() - 1) {
                // Not a key=value token. Ignored rather than fatal: the
                // required keys below decide, and a provider that adds a word
                // must not break a client that does not know it yet.
                continue;
            }
            String key = token.substring(0, eq);
            String value = token.substring(eq + 1);
            if (values.putIfAbsent(key, value) != null) {
                return refuse("duplicate signal " + key + "; two reports may have been merged");
            }
        }
        String level = values.get(KEY_ATTESTATION);
        if (level == null) {
            return refuse("the provider named no attestation level");
        }
        if (!ATTEST_NONE.equals(level) && !ATTEST_ROOT_OPERATIONAL.equals(level)
                && !ATTEST_RMG_CONTRACT.equals(level)) {
            // An unrecognised enum value refuses (AGENTS.md §2). A newer
            // provider inventing a level this build does not know is exactly
            // the case where believing it would be worst.
            return refuse("unrecognised attestation level " + level);
        }

        boolean rootOperation = pass(values, KEY_ROOT_OPERATION);
        boolean ksudPinned = pass(values, KEY_KSUD_PINNED);
        boolean contractRoundTrip = pass(values, KEY_CONTRACT_ROUNDTRIP);
        boolean selinux = pass(values, KEY_SELINUX);
        boolean moduleNamed = pass(values, KEY_MODULE_NAMED);

        /*
         * The level is RE-DERIVED here, from the same three facts the companion
         * derives it from, and then cross-checked against what it claimed.
         */
        boolean derived = rootOperation && ksudPinned && contractRoundTrip;
        boolean claimed = ATTEST_RMG_CONTRACT.equals(level);
        if (derived != claimed) {
            return refuse("the provider's attestation level (" + level + ") disagrees with"
                    + " its own signals (root=" + rootOperation + " pinned=" + ksudPinned
                    + " roundtrip=" + contractRoundTrip + ")");
        }
        return new Verdict(derived, rootOperation, ksudPinned, contractRoundTrip,
                selinux, moduleNamed,
                derived
                        ? "the provider attested the RMG pair and this side re-derived it"
                        : "the provider did not attest the RMG pair (level " + level + ")");
    }
}
