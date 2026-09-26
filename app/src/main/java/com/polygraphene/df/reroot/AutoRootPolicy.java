package com.polygraphene.df.reroot;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Pure scheduling policy for Auto Root after a full boot.
 *
 * Everything that DECIDES whether an automatic attempt may start lives here, with
 * no Android imports, for the reason AGENTS.md section 5 gives: the interesting
 * paths are the ones that only occur on hardware - a soft reboot that keeps the
 * boot id, a journal left behind by a run that died after the page-cache writes,
 * a qualification record belonging to a different build. None of those are
 * reachable from an instrumented test, and all of them are reachable from here.
 *
 * Two records are parsed, both written by {@code AutoRootStore} into
 * device-protected app storage:
 *
 * <pre>
 *   qualification   durable; says a MANUAL run once ended in a verified
 *                   same-boot POST_ROOT_COMPLETE on this exact build and this
 *                   exact firmware, and that the owner then opted in
 *   journal         per-boot; says what an automatic attempt already did in the
 *                   boot it names
 * </pre>
 *
 * Neither record is ever authority to root anything. They can only ever REMOVE
 * permission: the native chain re-runs every identity, module-policy and
 * post-root gate on its own evidence afterwards. That asymmetry is the point -
 * an attacker who can forge these files gains nothing but the ability to make
 * DFReroot refuse.
 *
 * Fail-closed shape, identical to {@link PostRootStatus}: an absent record, an
 * unparsable record, an unknown key, a duplicate key or a missing field all
 * refuse. Absence is never agreement.
 */
public final class AutoRootPolicy {

    /** Marks a qualification record produced by a verified manual completion. */
    public static final String STATE_QUALIFIED = "QUALIFIED";

    /** Journal phases, in the order a boot can pass through them. */
    public static final String PHASE_PREFLIGHT = "PREFLIGHT";
    public static final String PHASE_STARTED = "STARTED";
    public static final String PHASE_COMPLETE = "COMPLETE";
    public static final String PHASE_FAILED_LOCKED = "FAILED_LOCKED";

    /**
     * How many pre-STARTED readiness polls one boot may make, in total, across
     * however many times the service is started in that boot.
     *
     * Bounded on purpose, and bounded HERE rather than by an alarm or a job:
     * "never schedule an infinite retry loop" is a property of this number plus
     * the service's single thread, not of a scheduler's good behaviour.
     *
     * It has to be large enough for a real boot. LOCKED_BOOT_COMPLETED arrives
     * well before `sys.boot_completed` is 1, so the first polls always fail;
     * with a cap of 3 the readiness window closed after about a minute and any
     * slower boot was skipped entirely. The time budget in DfrAutoRootService is
     * meant to be what binds, and this number is only the backstop that keeps
     * the loop finite.
     */
    public static final int MAX_ATTEMPTS_PER_BOOT = 12;

    /**
     * What the store passes when a record EXISTS but could not be read.
     *
     * Distinguishing this from "no record" is load-bearing for the journal: a
     * missing journal means this boot has done nothing, while an unreadable one
     * may be hiding a STARTED from an attempt that already wrote to the page
     * cache. Collapsing the two would turn an I/O error into permission to run
     * again. It never parses, so every reader refuses it; the constant exists so
     * the refusal names the real cause.
     */
    public static final String RECORD_UNREADABLE = "dfr_record_unreadable";

    /**
     * How long after a kernel boot a boot broadcast may still start an attempt.
     *
     * This is a BOUND, not a proof. Android offers no signal that says "this
     * BOOT_COMPLETED belongs to a fresh kernel boot": a framework restart
     * re-broadcasts it with an unchanged boot_id, and if nothing of ours ran in
     * that boot there is no stored evidence to compare against either. Time since
     * kernel boot is the only remaining discriminator, and it fails in the safe
     * direction: a boot slow enough to exceed this simply does not get an
     * automatic attempt, while a framework restart hours into a session is
     * refused. What it does not exclude is a framework restart within the window
     * of a fresh boot in which nothing of ours ran - and that is a fresh kernel
     * boot with no prior attempt, which is the benign shape.
     */
    public static final long MAX_BOOT_WINDOW_MS = 10 * 60 * 1000L;

    /** Tri-state for the NetworkStack readiness probe. */
    public static final int PROCESS_PRESENT = 1;
    public static final int PROCESS_ABSENT = 0;
    public static final int PROCESS_UNKNOWN = -1;

    /**
     * Tri-state for the /dev/df + dfm1..dfm4 probe.
     *
     * A marker probe that answers yes/no reports a failed lookup as "absent",
     * which is the one answer that lets a run proceed. The native side already
     * refuses to collapse this (`has_mark()` returns -1 for undeterminable), and
     * the same rule applies here: only a positive ABSENT may permit a run.
     */
    public static final int MARKER_PRESENT = 1;
    public static final int MARKER_ABSENT = 0;
    public static final int MARKER_UNKNOWN = -1;

    private static final Set<String> QUALIFICATION_KEYS = Set.of(
            "state", "opt_in", "opt_in_boot_id", "version_code", "version_name",
            "ksud_sha256", "device_fingerprint", "boot_id", "recorded_at_ms");

    private static final Set<String> JOURNAL_KEYS = Set.of(
            "boot_id", "phase", "attempts", "native_started");

    private AutoRootPolicy() {}

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** What the policy was asked about. Immutable; assembled by the service. */
    public static final class Inputs {
        public String qualificationRecord;
        public String journalRecord;
        public String currentBootId;
        public String deviceFingerprint;
        public String ksudSha256;
        public String versionName;
        public int versionCode;
        public boolean bootCompleted;
        /** One of MARKER_PRESENT / MARKER_ABSENT / MARKER_UNKNOWN. */
        public int markerState = MARKER_UNKNOWN;
        /**
         * Milliseconds since kernel boot when the boot broadcast ARRIVED, not
         * when this poll runs: a readiness loop may span minutes, and the
         * question is how close to the boot the trigger was. Negative means it
         * could not be read, which refuses.
         */
        public long broadcastUptimeMs = -1;
        /** 1, 0, or -1 when /sys/fs/selinux/enforce could not be read. */
        public int liveSelinux = -1;
        /** One of PROCESS_PRESENT / PROCESS_ABSENT / PROCESS_UNKNOWN. */
        public int networkStack = PROCESS_UNKNOWN;
    }

    /**
     * The answer.
     *
     * {@code retryable} is separate from {@code allow} because the two failures
     * are different facts: "the framework is not up yet" may be asked again in
     * this boot, "this build was never qualified" may not, and collapsing them
     * would either block a legitimate boot or spin forever on a permanent
     * refusal.
     */
    public static final class Decision {
        public final boolean allow;
        public final boolean retryable;
        public final String reason;

        private Decision(boolean allow, boolean retryable, String reason) {
            this.allow = allow;
            this.retryable = retryable;
            this.reason = reason;
        }
    }

    private static Decision refuse(String reason) {
        return new Decision(false, false, reason);
    }

    private static Decision waitAndRetry(String reason) {
        return new Decision(false, true, reason);
    }

    /**
     * Strict key=value reader. Unknown and duplicate keys refuse rather than
     * being ignored, so a record written by a newer build - or half-written by
     * one that crashed - cannot be read as a subset of itself.
     */
    private static Map<String, String> parse(String record, Set<String> keys) {
        if (blank(record)) return null;
        Map<String, String> out = new HashMap<>();
        for (String raw : record.split("\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int sep = line.indexOf('=');
            if (sep <= 0 || sep == line.length() - 1) return null;
            String key = line.substring(0, sep);
            if (!keys.contains(key)) return null;
            if (out.putIfAbsent(key, line.substring(sep + 1)) != null) return null;
        }
        if (!out.keySet().equals(keys)) return null;
        return out;
    }

    /** Canonical qualification record. Written only after a verified manual PASS. */
    public static String formatQualification(int versionCode, String versionName,
                                            String ksudSha256, String deviceFingerprint,
                                            String bootId, long recordedAtMs,
                                            boolean optIn, String optInBootId) {
        StringBuilder s = new StringBuilder();
        s.append("state=").append(STATE_QUALIFIED).append('\n');
        s.append("opt_in=").append(optIn ? 1 : 0).append('\n');
        // The boot the switch was last touched in. Empty is not representable -
        // the parser refuses a valueless field - so a caller with no boot id has
        // nothing to write, which is itself a refusal.
        s.append("opt_in_boot_id=").append(optInBootId).append('\n');
        s.append("version_code=").append(versionCode).append('\n');
        s.append("version_name=").append(versionName).append('\n');
        s.append("ksud_sha256=").append(ksudSha256).append('\n');
        s.append("device_fingerprint=").append(deviceFingerprint).append('\n');
        s.append("boot_id=").append(bootId).append('\n');
        s.append("recorded_at_ms=").append(recordedAtMs).append('\n');
        return s.toString();
    }

    /** Canonical per-boot journal record. */
    public static String formatJournal(String bootId, String phase, int attempts,
                                      boolean nativeStarted) {
        StringBuilder s = new StringBuilder();
        s.append("boot_id=").append(bootId).append('\n');
        s.append("phase=").append(phase).append('\n');
        s.append("attempts=").append(attempts).append('\n');
        s.append("native_started=").append(nativeStarted ? 1 : 0).append('\n');
        return s.toString();
    }

    /**
     * Rewrite an existing qualification record's opt-in flag, keeping every
     * other field. Returns null when the record cannot be read, so a toggle can
     * never CREATE a qualification - only a verified manual run does that.
     */
    public static String withOptIn(String qualificationRecord, boolean optIn,
                                   String currentBootId) {
        if (RECORD_UNREADABLE.equals(qualificationRecord)) return null;
        if (blank(currentBootId)) return null;
        Map<String, String> q = parse(qualificationRecord, QUALIFICATION_KEYS);
        if (q == null) return null;
        long recordedAt;
        try {
            recordedAt = Long.parseLong(q.get("recorded_at_ms"));
        } catch (NumberFormatException ex) {
            return null;
        }
        int code;
        try {
            code = Integer.parseInt(q.get("version_code"));
        } catch (NumberFormatException ex) {
            return null;
        }
        return formatQualification(code, q.get("version_name"), q.get("ksud_sha256"),
                q.get("device_fingerprint"), q.get("boot_id"), recordedAt, optIn,
                currentBootId.trim());
    }

    /** Whether a record exists, parses, and carries opt_in=1 for this build. */
    public static boolean isOptedIn(String qualificationRecord, int versionCode,
                                    String versionName, String ksudSha256,
                                    String deviceFingerprint) {
        Map<String, String> q = parse(qualificationRecord, QUALIFICATION_KEYS);
        if (q == null) return false;
        return STATE_QUALIFIED.equals(q.get("state"))
                && "1".equals(q.get("opt_in"))
                && buildMatches(q, versionCode, versionName, ksudSha256, deviceFingerprint) == null;
    }

    /** Whether a record exists and parses, regardless of the opt-in flag. */
    public static boolean isQualified(String qualificationRecord, int versionCode,
                                      String versionName, String ksudSha256,
                                      String deviceFingerprint) {
        Map<String, String> q = parse(qualificationRecord, QUALIFICATION_KEYS);
        if (q == null) return false;
        return STATE_QUALIFIED.equals(q.get("state"))
                && buildMatches(q, versionCode, versionName, ksudSha256, deviceFingerprint) == null;
    }

    /**
     * Returns null when the qualification belongs to this exact build on this
     * exact firmware, or the reason it does not.
     *
     * The ksud digest is in here because it is the one field that changes when
     * the daemon changes without the app's version necessarily moving, and the
     * device fingerprint because a firmware update is a different target - the
     * runtime identity gate would refuse it anyway, but an automatic attempt
     * should not be the thing that discovers that.
     */
    private static String buildMatches(Map<String, String> q, int versionCode,
                                       String versionName, String ksudSha256,
                                       String deviceFingerprint) {
        if (!Integer.toString(versionCode).equals(q.get("version_code"))) {
            return "qualification was recorded for versionCode " + q.get("version_code")
                    + ", this build is " + versionCode;
        }
        if (versionName == null || !versionName.equals(q.get("version_name"))) {
            return "qualification was recorded for version " + q.get("version_name");
        }
        if (ksudSha256 == null || !ksudSha256.equals(q.get("ksud_sha256"))) {
            return "qualification was recorded for a different ksud digest";
        }
        if (deviceFingerprint == null || !deviceFingerprint.equals(q.get("device_fingerprint"))) {
            return "qualification was recorded on a different firmware build";
        }
        return null;
    }

    /**
     * May an automatic attempt start now?
     *
     * Order matters: the cheap durable refusals come first so a device that was
     * never qualified never probes anything, and the retryable readiness checks
     * come last so a retryable answer is never returned for a permanent refusal.
     */
    public static Decision evaluate(Inputs in) {
        if (in == null) return refuse("no inputs");
        if (blank(in.currentBootId)) return refuse("current boot_id is unavailable");

        if (RECORD_UNREADABLE.equals(in.qualificationRecord)) {
            return refuse("the Auto Root qualification exists but could not be read");
        }
        Map<String, String> q = parse(in.qualificationRecord, QUALIFICATION_KEYS);
        if (q == null) {
            return refuse("no readable Auto Root qualification: a manual run must first"
                    + " end in verified same-boot POST_ROOT_COMPLETE");
        }
        if (!STATE_QUALIFIED.equals(q.get("state"))) {
            return refuse("qualification state is " + q.get("state"));
        }
        if (!"1".equals(q.get("opt_in"))) {
            return refuse("Auto Root is not opted in");
        }
        String mismatch = buildMatches(q, in.versionCode, in.versionName, in.ksudSha256,
                in.deviceFingerprint);
        if (mismatch != null) {
            return refuse(mismatch + "; qualification is invalidated until another"
                    + " manual PASS");
        }
        /*
         * The qualifying manual run belongs to a boot; if that is still the
         * current boot then no reboot has happened, and the whole premise of
         * "Auto Root after full boot" is absent. This is also the check that
         * makes a framework restart harmless: a soft reboot keeps boot_id, so
         * the qualification's boot_id keeps matching and nothing starts.
         */
        if (in.currentBootId.equals(q.get("boot_id"))) {
            return refuse("still in the boot that qualified Auto Root; a full reboot is"
                    + " required before an automatic attempt");
        }
        /*
         * And not in the boot it was ARMED in either.
         *
         * BOOT_COMPLETED is not evidence of a kernel boot: a framework restart
         * re-broadcasts it while boot_id stays the same. The journal catches that
         * only once this boot has a record, so the hole was the first broadcast of
         * a boot in which Auto Root was switched on after the framework was
         * already up - nothing had run, nothing was journalled, and the
         * qualifying boot was some earlier one, so every condition passed.
         *
         * Binding the switch to the boot it was flipped in closes it exactly,
         * rather than by a heuristic on uptime: arming can only ever take effect
         * in a LATER boot, which is what "Auto Root after full boot" means. Two
         * stored boot ids plus the journal now carry the guarantee, and no
         * property of the broadcast is trusted at all.
         */
        if (in.currentBootId.equals(q.get("opt_in_boot_id"))) {
            return refuse("Auto Root was switched on during this boot; it takes effect"
                    + " from the next full reboot (a framework restart keeps the same"
                    + " boot_id and is not one)");
        }
        /*
         * How long the kernel has been up when the trigger arrived.
         *
         * The two rules above only cover boots this code has stored something
         * about. A later boot in which nothing of ours ran leaves no record at
         * all, so a framework restart there differs from a fresh boot in exactly
         * one observable way: the kernel has been up for a long time. Bounding it
         * is therefore a necessary condition, not a sufficient one, and the
         * comment on MAX_BOOT_WINDOW_MS says what it does and does not establish.
         */
        if (in.broadcastUptimeMs < 0) {
            return refuse("time since kernel boot is unavailable; a boot trigger that"
                    + " cannot be placed in its boot is refused");
        }
        if (in.broadcastUptimeMs > MAX_BOOT_WINDOW_MS) {
            return refuse("the boot trigger arrived " + (in.broadcastUptimeMs / 1000)
                    + "s after kernel boot, past the " + (MAX_BOOT_WINDOW_MS / 1000)
                    + "s boot window; a framework restart re-broadcasts it and is not"
                    + " a full boot");
        }

        if (RECORD_UNREADABLE.equals(in.journalRecord)) {
            /*
             * An existing journal we cannot read is the worst case, not a blank
             * slate: it may say STARTED. Refuse the boot; a reboot clears it.
             */
            return refuse("the Auto Root journal exists but could not be read;"
                    + " refusing this boot");
        }
        if (in.journalRecord != null && !blank(in.journalRecord)) {
            Map<String, String> j = parse(in.journalRecord, JOURNAL_KEYS);
            if (j == null) {
                /*
                 * A journal that cannot be read may have been written by a run
                 * that died mid-write, which is exactly the case where another
                 * automatic attempt is least safe. Refuse the boot; a reboot
                 * clears it.
                 */
                return refuse("Auto Root journal is unreadable; refusing this boot");
            }
            if (in.currentBootId.equals(j.get("boot_id"))) {
                String phase = j.get("phase");
                /*
                 * Exact enum validation, before any of the branches below. A
                 * journal that parses but carries a phase or a flag this build
                 * does not know - a corrupted record, or one written by a newer
                 * version - is uncertain evidence about a boot that may already
                 * have run the chain. Falling through it to `allow` is the one
                 * outcome that must not be reachable.
                 */
                String nativeStarted = j.get("native_started");
                if (!"0".equals(nativeStarted) && !"1".equals(nativeStarted)) {
                    return refuse("Auto Root journal native_started is " + nativeStarted
                            + ", not 0 or 1");
                }
                if (!PHASE_PREFLIGHT.equals(phase) && !PHASE_STARTED.equals(phase)
                        && !PHASE_COMPLETE.equals(phase)
                        && !PHASE_FAILED_LOCKED.equals(phase)) {
                    return refuse("Auto Root journal phase is not a known state: " + phase);
                }
                if (PHASE_COMPLETE.equals(phase)) {
                    return refuse("Auto Root already completed in this boot");
                }
                if (PHASE_FAILED_LOCKED.equals(phase)) {
                    return refuse("Auto Root already failed in this boot; a hard reboot is"
                            + " the recovery boundary");
                }
                if (PHASE_STARTED.equals(phase) || "1".equals(j.get("native_started"))) {
                    return refuse("native execution already began in this boot; a hard"
                            + " reboot is the recovery boundary");
                }
                int attempts;
                try {
                    attempts = Integer.parseInt(j.get("attempts"));
                } catch (NumberFormatException ex) {
                    return refuse("Auto Root journal attempt count is not a number");
                }
                if (attempts < 0) {
                    return refuse("Auto Root journal attempt count is negative");
                }
                if (attempts >= MAX_ATTEMPTS_PER_BOOT) {
                    return refuse("Auto Root readiness attempts exhausted for this boot ("
                            + attempts + "/" + MAX_ATTEMPTS_PER_BOOT + ")");
                }
            }
            // A journal naming another boot is last boot's record: it says
            // nothing about this one and must not lock it.
        }

        /*
         * From here on, everything is observed state rather than stored state.
         * A marker is the hard one: /dev/df or any dfm marker means a DirtyFrag
         * run already armed hooks in this boot, and MainActivity refuses a second
         * run for the same reason. The automatic path gets no weaker rule.
         */
        if (in.markerState == MARKER_PRESENT) {
            return refuse("/dev/df or a stage marker is already present; only a hard"
                    + " reboot clears armed hooks");
        }
        if (in.markerState != MARKER_ABSENT) {
            // Not ENOENT, so the probe failed rather than finding nothing. An
            // unreadable /dev is not an empty /dev.
            return refuse("whether /dev/df or a stage marker exists could not be"
                    + " determined; refusing rather than assuming a clean boot");
        }
        if (in.liveSelinux != 1) {
            return refuse("initial /sys/fs/selinux/enforce is " + in.liveSelinux
                    + ", expected 1 (unreadable reads as -1 and also refuses)");
        }
        if (!in.bootCompleted) {
            return waitAndRetry("sys.boot_completed is not 1 yet");
        }
        if (in.networkStack == PROCESS_ABSENT) {
            return waitAndRetry("NETWORKSTACK_PROCESS_FOUND=0 (not running yet)");
        }
        if (in.networkStack == PROCESS_UNKNOWN) {
            /*
             * Deliberately NOT a refusal, and deliberately not silent either.
             * Whether a process with the NetworkStack uid is visible in /proc
             * depends on procfs visibility, not on the chain's health, and this
             * probe gates nothing destructive: the hop performs its own
             * authoritative AMS lookup and ends on PROCESS_LOOKUP=PASS|FAIL
             * before a single page-cache byte is written. Per AGENTS.md 3.7 the
             * two facts stay separate rather than one standing in for the other.
             */
            return new Decision(true, false,
                    "PREFLIGHT=PASS with NETWORKSTACK_PROCESS_FOUND=UNKNOWN;"
                            + " the hop's own PROCESS_LOOKUP remains authoritative");
        }
        return new Decision(true, false, "PREFLIGHT=PASS");
    }

    /**
     * Whether a finished run may be recorded as a qualification.
     *
     * The same conjunction the UI uses for success, restated where it can be
     * tested: a native result of 0 is bootstrap completion, not root, so it
     * cannot qualify anything on its own.
     */
    public static boolean qualifies(int nativeResult, boolean postRootComplete,
                                    int liveSelinux) {
        return nativeResult == 0 && postRootComplete && liveSelinux == 1;
    }
}
