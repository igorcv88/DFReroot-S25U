package com.polygraphene.df.companion;

/**
 * May this caller ask for a root operation? Pure: facts in, a verdict out.
 *
 * <h2>What it can and cannot establish — read this before trusting it</h2>
 *
 * DFReroot lives in {@code android.uid.system}. Dozens of platform packages
 * share that uid, so {@code getPackagesForUid(1000)} returns all of them and
 * Binder gives us the uid, not the process. This check therefore establishes:
 *
 * <ul>
 *   <li>the caller is uid 1000 — the platform shared uid; and</li>
 *   <li>{@code com.polygraphene.df.reroot} is installed in that uid, signed by
 *       the same certificate as this companion.</li>
 * </ul>
 *
 * It does <b>not</b> establish that the calling process is DFReroot rather than
 * another member of that shared uid. That is not a gap this code can close —
 * the platform does not offer a finer answer for a shared uid — so it is stated
 * here instead of being implied away, and it is the reason the v1 contract
 * exposes a fixed non-destructive attestation and no command channel
 * ({@link CompanionContract}). An interface whose caller cannot be identified
 * precisely must not be able to do anything that matters.
 *
 * The signature-level manifest permission is a separate, earlier check by the
 * framework. Both run: the permission answers "may you call", this answers
 * "who, as far as the platform can say".
 */
public final class CallerAuthorization {

    private CallerAuthorization() {}

    public static final class Verdict {
        public final boolean allowed;
        public final int rc;
        public final String reason;

        private Verdict(boolean allowed, int rc, String reason) {
            this.allowed = allowed;
            this.rc = rc;
            this.reason = reason;
        }
    }

    private static Verdict refuse(int rc, String reason) {
        return new Verdict(false, rc, reason);
    }

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** A lowercase 64-hex digest, or nothing. Anything else is not evidence. */
    private static boolean digest(String s) {
        if (s == null || s.length() != 64) return false;
        for (int i = 0; i < 64; i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }

    /**
     * @param callingUid          {@code Binder.getCallingUid()}
     * @param packagesForUid      every package in that uid, or null when the
     *                            lookup failed. Null is a refusal: an empty
     *                            answer and a failed one are not the same fact,
     *                            and neither is permission.
     * @param clientDigest        SHA-256 of the client package's signing
     *                            certificate, as the platform reports it
     * @param ownDigest           SHA-256 of this companion's own certificate
     * @param requestedVersion    the contract version the caller sent
     */
    public static Verdict evaluate(
            int callingUid,
            String[] packagesForUid,
            String clientDigest,
            String ownDigest,
            int requestedVersion) {

        if (requestedVersion != CompanionContract.CONTRACT_VERSION) {
            return refuse(CompanionContract.RC_VERSION_MISMATCH,
                    "caller asked for contract v" + requestedVersion + "; this companion"
                            + " speaks v" + CompanionContract.CONTRACT_VERSION);
        }
        if (callingUid != CompanionContract.CLIENT_UID) {
            return refuse(CompanionContract.RC_CALLER_REFUSED,
                    "calling uid " + callingUid + " is not the platform uid "
                            + CompanionContract.CLIENT_UID);
        }
        if (packagesForUid == null) {
            return refuse(CompanionContract.RC_CALLER_REFUSED,
                    "the package list for the calling uid could not be obtained;"
                            + " an unanswered lookup is not an identity");
        }
        boolean present = false;
        for (String p : packagesForUid) {
            if (CompanionContract.CLIENT_PACKAGE.equals(p)) {
                present = true;
                break;
            }
        }
        if (!present) {
            return refuse(CompanionContract.RC_CALLER_REFUSED,
                    CompanionContract.CLIENT_PACKAGE + " is not installed in the calling uid");
        }
        if (!digest(clientDigest) || !digest(ownDigest)) {
            return refuse(CompanionContract.RC_CALLER_REFUSED,
                    "a signing certificate digest was unavailable or malformed;"
                            + " refusing rather than skipping the comparison");
        }
        if (!clientDigest.equalsIgnoreCase(ownDigest)) {
            return refuse(CompanionContract.RC_CALLER_REFUSED,
                    "the client is signed by a different certificate than this companion");
        }
        return new Verdict(true, CompanionContract.RC_OK,
                "uid " + callingUid + " carries " + CompanionContract.CLIENT_PACKAGE
                        + " signed by this companion's certificate (shared uid: the"
                        + " process itself is not distinguishable)");
    }
}
