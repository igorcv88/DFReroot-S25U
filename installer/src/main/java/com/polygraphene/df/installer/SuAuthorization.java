package com.polygraphene.df.installer;

/**
 * What happened when DFInstaller asked for root, told apart from one another.
 *
 * <p>WHY THIS EXISTS. The installer decided it had root with
 * {@code rootOut.contains("uid=0")} over a string that already had stdout,
 * stderr and {@code [rc=N]} concatenated into it. Three different failures
 * reached the user as one message, "obtain temporary root first":
 *
 * <ul>
 *   <li>there is no {@code su} on PATH at all;
 *   <li>{@code su} exists and <em>refused</em> this caller;
 *   <li>{@code su} ran and returned some identity that is not uid 0.
 * </ul>
 *
 * <p>Telling them apart is not cosmetic here. Without a KernelSU Manager APK
 * there is no prompt to approve: authorization for this package is granted
 * out of band, so "su refused DFInstaller" is an instruction to go and
 * authorize this package, while "no su" is an instruction to obtain temporary
 * root first. Reporting the first as the second sends the owner to re-run an
 * exploit that was never the problem.
 *
 * <p>The substring test was also unsound in the permissive direction, which
 * matters more than the message: any output containing the three characters
 * {@code uid=0} anywhere - a denial that echoes the caller's request, a
 * diagnostic line, a package name - enabled every privileged button. The exit
 * status was not consulted at all. So this class reads uid only from a line
 * {@code id(1)} actually produced, and only when the process also succeeded.
 *
 * <p>Pure by construction - no Android imports, no process spawning - because
 * the states that matter cannot be produced on demand on a device. Refusing a
 * caller requires an unauthorized package; a non-zero uid requires a
 * half-granted shell. Both are one method call away from a host test, and
 * {@code tools/tests/SuAuthorizationTest.java} is where they live.
 *
 * <p>This class decides nothing about privilege. It classifies an observation.
 * It never asks for root, never widens an authorization, and the only verdict
 * that permits anything is {@link Verdict#ROOT_OK}.
 */
public final class SuAuthorization {

    /** The distinguishable outcomes of asking {@code su} to run {@code id}. */
    public enum Verdict {
        /** uid 0, confirmed from {@code id} output on a successful process. */
        ROOT_OK,
        /** No {@code su} binary could be executed at all. */
        SU_ABSENT,
        /** {@code su} ran and did not grant: refused, or died non-zero. */
        SU_DENIED,
        /** {@code su} granted something, and it was not uid 0. */
        SU_WRONG_IDENTITY,
        /** {@code su} succeeded but printed nothing {@code id}-shaped. */
        SU_UNINTELLIGIBLE
    }

    /** A verdict, the uid behind it when one was read, and why. */
    public static final class Result {
        private final Verdict verdict;
        private final int uid;
        private final String detail;

        Result(Verdict verdict, int uid, String detail) {
            this.verdict = verdict;
            this.uid = uid;
            this.detail = detail;
        }

        public Verdict verdict() {
            return verdict;
        }

        /** The uid read from {@code id}, or -1 when none was read. */
        public int uid() {
            return uid;
        }

        /** One line, already boundary-tagged, safe to show and to log. */
        public String detail() {
            return detail;
        }

        /**
         * The single question the UI may ask. Everything privileged in
         * DFInstaller is gated on this, so it is deliberately the only method
         * that turns a verdict into permission, and only one verdict does.
         */
        public boolean rooted() {
            return verdict == Verdict.ROOT_OK;
        }
    }

    private SuAuthorization() {
    }

    /**
     * Classify one {@code su -c id} attempt.
     *
     * @param execFailed the process could not be started at all
     * @param exitCode   its exit status, meaningless when execFailed
     * @param stdout     its standard output, never null
     * @param stderr     its standard error, never null
     */
    public static Result classify(boolean execFailed, int exitCode,
                                  String stdout, String stderr) {
        if (execFailed) {
            return new Result(Verdict.SU_ABSENT, -1,
                    "[DFR][su] no su binary could be executed; obtain "
                    + "temporary root first");
        }
        if (exitCode != 0) {
            // A refusal is the expected shape here, and under a managerless
            // contract it is also the actionable one: there is no Manager to
            // prompt, so this package's authorization is granted elsewhere.
            return new Result(Verdict.SU_DENIED, -1,
                    "[DFR][su] su exited " + exitCode + "; root was not "
                    + "granted to DFInstaller. Without a Manager APK this "
                    + "package must be authorized out of band"
                    + firstLineSuffix(stderr));
        }
        // Only stdout, and only a line id(1) would have written. stderr is
        // excluded on purpose: a denial that quotes the request back is the
        // exact input that made the old substring test answer yes.
        int uid = readUid(stdout);
        if (uid < 0) {
            return new Result(Verdict.SU_UNINTELLIGIBLE, -1,
                    "[DFR][su] su succeeded but printed no id(1) uid field; "
                    + "refusing to infer an identity"
                    + firstLineSuffix(stdout));
        }
        if (uid != 0) {
            return new Result(Verdict.SU_WRONG_IDENTITY, uid,
                    "[DFR][su] su granted uid " + uid + ", not 0; DFInstaller "
                    + "needs uid 0 to edit packages.xml");
        }
        return new Result(Verdict.ROOT_OK, 0, "[DFR][su] uid 0 confirmed");
    }

    /**
     * The uid from {@code id} output, or -1.
     *
     * <p>{@code id} writes {@code uid=0(root) gid=0(root) groups=...} as the
     * start of a line. Requiring the field at a line start, rather than
     * anywhere, is what stops prose that merely mentions it from counting -
     * and a line that starts with a uid field but whose digits do not parse is
     * -1 rather than a guess.
     */
    static int readUid(String stdout) {
        if (stdout == null) {
            return -1;
        }
        for (String raw : stdout.split("\n", -1)) {
            String line = raw.trim();
            if (!line.startsWith("uid=")) {
                continue;
            }
            int i = 4;
            int end = i;
            while (end < line.length() && Character.isDigit(line.charAt(end))) {
                end++;
            }
            if (end == i) {
                // "uid=" with no digits: malformed, and malformed is not a pass.
                return -1;
            }
            // The next character must end the field the way id(1) ends it.
            if (end < line.length()) {
                char c = line.charAt(end);
                if (c != '(' && c != ' ' && c != '\t' && c != '\r') {
                    return -1;
                }
            }
            try {
                return Integer.parseInt(line.substring(i, end));
            } catch (NumberFormatException e) {
                // A uid too large for int is not uid 0, and must not be
                // rounded, clamped or guessed into one.
                return -1;
            }
        }
        return -1;
    }

    /** First non-blank line of a stream, bracketed, for the diagnostic line. */
    private static String firstLineSuffix(String stream) {
        if (stream == null) {
            return "";
        }
        for (String raw : stream.split("\n", -1)) {
            String line = raw.trim();
            if (!line.isEmpty()) {
                return " (" + line + ")";
            }
        }
        return "";
    }
}
