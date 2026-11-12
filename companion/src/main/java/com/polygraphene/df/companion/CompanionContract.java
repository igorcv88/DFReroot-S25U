package com.polygraphene.df.companion;

/**
 * The wire contract between DFReroot and this companion. Pure constants.
 *
 * <h2>Why a companion exists at all</h2>
 *
 * DFReroot runs entirely inside {@code system_server} ({@code sharedUserId=
 * android.uid.system}, {@code android:process="system"}). Two independent
 * consequences follow, and together they rule out every in-app alternative:
 *
 * <ul>
 *   <li>The RMG managerless grant contract refuses shared-UID peers and
 *       requires an appId in 10000..19999, so DFReroot <b>cannot be granted
 *       root</b> by the pair installed on the device. Not "has not been" —
 *       cannot be.</li>
 *   <li>That domain holds {@code map}/{@code read} but not {@code execute}/
 *       {@code execmod} on {@code apk_data_file}, so it can neither exec a
 *       helper from {@code /data} nor map its own native library. The KernelSU
 *       prctl/ioctl UAPI is therefore out of reach from there as well.</li>
 * </ul>
 *
 * A separate app with its own uid has none of those problems, and the grant is
 * a runtime operation ({@code ksud profile grant <package>} from any full-root
 * KSU process) — no module rebuild, no new pair.
 *
 * <h2>Version 1 declares two transactions and no command channel</h2>
 *
 * There is deliberately no "run this string as root" transaction. An exported
 * interface that executes caller-supplied commands as root is a root shell with
 * extra steps, and the caller cannot be identified precisely enough to justify
 * one (see {@link CallerAuthorization} on shared uids). Version 1 therefore
 * exposes a fixed, enumerated, non-destructive attestation and nothing else.
 * Adding an operation means adding a transaction here, with its own gate.
 */
public final class CompanionContract {

    private CompanionContract() {}

    public static final String PACKAGE = "com.polygraphene.df.companion";
    public static final String ACTION = "com.polygraphene.df.companion.ROOT_OPERATIONS";
    public static final String PERMISSION =
            "com.polygraphene.df.companion.permission.ROOT_OPERATIONS";

    /** The one package authorized to call, and the uid it necessarily runs as. */
    public static final String CLIENT_PACKAGE = "com.polygraphene.df.reroot";
    public static final int CLIENT_UID = 1000;

    /**
     * Bumped whenever a transaction's meaning, arguments or report keys change.
     *
     * Both sides compare it and refuse on a mismatch rather than interpreting
     * an older peer's bytes optimistically: an app and a companion are updated
     * separately, so a version skew is the normal case, not the exception.
     */
    public static final int CONTRACT_VERSION = 1;

    /**
     * The Binder interface token. Written by the caller, enforced by the
     * service: a third check beside the signature permission and
     * {@link CallerAuthorization}, and the cheapest of the three. It costs
     * nothing and it refuses a transaction aimed at this code by accident.
     */
    public static final String DESCRIPTOR = "com.polygraphene.df.companion.ICompanion";

    /** Contract version and capability list. Takes no root and reads nothing. */
    public static final int TX_DESCRIBE = 1;
    /** The bounded, non-destructive attestation. Needs the grant. */
    public static final int TX_ATTEST = 2;

    public static final int RC_OK = 0;
    public static final int RC_CALLER_REFUSED = 1;
    public static final int RC_VERSION_MISMATCH = 2;
    public static final int RC_NO_ROOT = 3;
    public static final int RC_TIMEOUT = 4;
    public static final int RC_UNAVAILABLE = 5;
    public static final int RC_UNKNOWN_TRANSACTION = 6;
    /** The attestation ran and its evidence did not support any claim. */
    public static final int RC_ATTESTATION_INCONCLUSIVE = 7;

    /** Deadline for one attestation, including the su grant and the shell. */
    public static final long ATTEST_TIMEOUT_MS = 20_000L;

    public static String rcName(int rc) {
        switch (rc) {
            case RC_OK: return "OK";
            case RC_CALLER_REFUSED: return "CALLER_REFUSED";
            case RC_VERSION_MISMATCH: return "VERSION_MISMATCH";
            case RC_NO_ROOT: return "NO_ROOT";
            case RC_TIMEOUT: return "TIMEOUT";
            case RC_UNAVAILABLE: return "UNAVAILABLE";
            case RC_UNKNOWN_TRANSACTION: return "UNKNOWN_TRANSACTION";
            case RC_ATTESTATION_INCONCLUSIVE: return "ATTESTATION_INCONCLUSIVE";
            default: return "RC_" + rc;
        }
    }
}
