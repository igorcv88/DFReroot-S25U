package com.polygraphene.df.reroot;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Pure policy for Early Integrated Root: the chain dispatched from the persisted
 * JobScheduler callback, inside the boot animation, before
 * {@code LOCKED_BOOT_COMPLETED}.
 *
 * ## Why this is not {@link AutoRootPolicy} with one condition relaxed
 *
 * {@code AutoRootPolicy.evaluate()} contains {@code if (!in.bootCompleted) return
 * waitAndRetry(...)}, and that is not an accident to be edited away: Auto Root is
 * defined as "after a full boot", its retry budget assumes a framework that is
 * already up, and its boot window is ten minutes wide because a late
 * {@code BOOT_COMPLETED} is the only thing it has to place itself in a boot.
 * Deleting that one line would have produced a policy that claims to be two
 * different things at once, and the next agent reading it could not have told
 * which conditions belonged to which caller.
 *
 * So the early window gets its own policy, with its own evidence, and the two
 * share the only thing they should share: {@link DfrRootCoordinator}, the single
 * execution path. Nothing here weakens a gate the coordinator runs.
 *
 * ## What replaces {@code sys.boot_completed}
 *
 * {@code sys.boot_completed} was never the fact Auto Root needed; it was a proxy
 * for "the framework can serve the hop". In the early window that proxy is false
 * by construction and the real fact is directly observable:
 * {@link StageHop#probeReadiness} resolves the NetworkStack process, the AMS
 * {@code ProcessRecord}, the {@code IApplicationThread} and
 * {@code scheduleReceiver/12} - the four things the hop actually uses. So this
 * policy requires {@code NETWORKSTACK_READY} exactly, which is strictly stronger
 * evidence about the hop than the property it replaces, and refuses
 * {@code PARTIAL} and {@code NOT_READY} alike.
 *
 * ## One shot, armed in the open
 *
 * There is deliberately no persistent "always root early" flag. The owner arms
 * one one-shot job for the next boot; the scheduler consumes it; the next boot
 * needs a new arming. That is the fail-closed shape for an operation whose worst
 * outcome is not a refusal (AGENTS.md 3.6.1): the page-cache writes happen while
 * the firmware's own boot watchdog is still deciding whether this boot
 * completed, and nobody has yet observed what that costs. A persistent form is a
 * promotion for after that evidence exists, not a default to ship ahead of it.
 *
 * Fail-closed in the same shape as every other record here: absent, unreadable,
 * malformed, an unknown key, a duplicate key, an unrecognised enum value and a
 * failed clock reading all refuse. Absence is never agreement.
 *
 * Nothing stored here is authority to root anything. These records can only
 * REMOVE permission - the native chain re-runs every identity, module-policy and
 * post-root gate on its own evidence afterwards. Forging them buys a refusal.
 */
public final class EarlyRootPolicy {

    /** Marks an arm record the owner created for the NEXT full boot. */
    public static final String STATE_ARMED = "EARLY_ROOT_ARMED";

    /**
     * Identity of the persisted job, distinct from the observation-only probe's.
     *
     * Two separate jobs, not one job with a mode, and the separation is
     * load-bearing in both directions. The probe must stay observation-only or
     * the measurement that found this window stops being repeatable - it exists
     * to time itself against {@code LOCKED_BOOT_COMPLETED}, and a root chain on
     * that looper would move the thing being measured. And a dispatch that can
     * reach {@code transact(5)} must not be reachable by arming a probe, which
     * is what one shared job id would have meant.
     *
     * uid 1000 is shared with every system component, so the job id alone proves
     * nothing; the namespace plus the component check in {@link DfrEarlyRoot} is
     * what binds the callback to us.
     */
    public static final int EXPECTED_JOB_ID = 0x44465252; // "DFRR"
    public static final String EXPECTED_NAMESPACE = "dfr-early-root";
    public static final String DEFAULT_UID_NAMESPACE =
            EarlyBootProbePolicy.DEFAULT_UID_NAMESPACE;

    /** One attempt per boot. The job is one-shot; this is the durable half. */
    public static final int MAX_ATTEMPTS_PER_BOOT = 1;

    /**
     * How long after kernel boot a callback may still be treated as "early".
     *
     * A BOUND, not a proof, and bounded for a different reason than
     * {@link AutoRootPolicy#MAX_BOOT_WINDOW_MS}. That one exists because a
     * framework restart is indistinguishable from a fresh boot; here the arm
     * record's {@code armed_boot_id} already settles the boot (a restart keeps
     * the boot id, so an arming boot can never fire its own early root). What
     * this bounds is the WINDOW: "early" means inside the boot animation, and a
     * persisted job that the scheduler restores minutes late is not in that
     * window at all. The three captured boots entered the callback at 14.6 s,
     * 14.6 s and 16.9 s; two minutes leaves an order of magnitude of slack for a
     * slow boot and still refuses a callback that arrives where Auto Root's path
     * is the correct one.
     *
     * Exceeding it is a refusal rather than a fall-through to the normal path,
     * because a fall-through would be a second implementation of Auto Root's
     * policy under a different name - and Auto Root's own trigger still runs in
     * that boot anyway.
     */
    public static final long EARLY_WINDOW_MS = 120_000L;

    /** Verdict codes. Separate values because they are separate facts (3.7). */
    public static final String ALLOW = "EARLY_ROOT_ALLOW";
    public static final String NO_BOOT_ID = "EARLY_ROOT_NO_BOOT_ID";
    public static final String ARM_NO_RECORD = "EARLY_ROOT_NOT_ARMED";
    public static final String ARM_UNREADABLE = "EARLY_ROOT_ARM_UNREADABLE";
    public static final String ARM_MALFORMED = "EARLY_ROOT_ARM_MALFORMED";
    public static final String ARM_SAME_BOOT = "EARLY_ROOT_ARMED_THIS_BOOT";
    public static final String BINDING_MISMATCH = "EARLY_ROOT_SCHEDULER_BINDING_MISMATCH";
    public static final String BUILD_MISMATCH = "EARLY_ROOT_BUILD_MISMATCH";
    public static final String NOT_QUALIFIED = "EARLY_ROOT_NOT_QUALIFIED";
    public static final String CLOCK_UNAVAILABLE = "EARLY_ROOT_CLOCK_UNAVAILABLE";
    public static final String PAST_WINDOW = "EARLY_ROOT_PAST_EARLY_WINDOW";
    public static final String JOURNAL_UNREADABLE = "EARLY_ROOT_JOURNAL_UNREADABLE";
    public static final String JOURNAL_MALFORMED = "EARLY_ROOT_JOURNAL_MALFORMED";
    public static final String BOOT_SPENT = "EARLY_ROOT_BOOT_ALREADY_ATTEMPTED";
    public static final String AUTO_JOURNAL_UNREADABLE =
            "EARLY_ROOT_AUTO_ROOT_JOURNAL_UNREADABLE";
    public static final String AUTO_JOURNAL_MALFORMED =
            "EARLY_ROOT_AUTO_ROOT_JOURNAL_MALFORMED";
    public static final String AUTO_BOOT_SPENT = "EARLY_ROOT_AUTO_ROOT_ALREADY_ATTEMPTED";
    public static final String MARKER_PRESENT = "EARLY_ROOT_MARKER_PRESENT";
    public static final String MARKER_UNKNOWN = "EARLY_ROOT_MARKER_UNKNOWN";
    public static final String SELINUX_NOT_ENFORCING = "EARLY_ROOT_SELINUX_NOT_ENFORCING";
    public static final String READINESS_REFUSED = "EARLY_ROOT_NETWORKSTACK_NOT_READY";

    /*
     * The durable trace steps, in the order one boot can pass through them.
     *
     * A fixed vocabulary rather than free-form strings, for the reason AGENTS.md
     * 3.6.1 gives: the last time a privileged step on this device went wrong,
     * what made it diagnosable was a record that could be READ afterwards, and
     * what nearly made it undiagnosable was reasoning from an absence. A typo'd
     * step name is a line nobody can account for, so writing one refuses.
     */
    public static final String STEP_JOB_ENTERED = "EARLY_ROOT_JOB_ENTERED";
    public static final String STEP_READINESS_PASS = "EARLY_ROOT_READINESS_PASS";
    public static final String STEP_DISPATCHED = "EARLY_ROOT_DISPATCHED";
    public static final String STEP_SERVICE_ENTERED = "EARLY_ROOT_SERVICE_ENTERED";
    public static final String STEP_PREFLIGHT_PASS = "EARLY_ROOT_PREFLIGHT_PASS";
    public static final String STEP_COORDINATOR_ENTERED = "EARLY_ROOT_COORDINATOR_ENTERED";
    /**
     * Staging is ABOUT to be attempted, not done.
     *
     * The coordinator reports {@code Phase.STAGE_KSUD} before it calls
     * {@code KsudStage.stageFromAssets()} and before the
     * {@code KSUD_STAGED_VERIFY=PASS} check, so a step called "STAGED" here
     * would claim the daemon was staged in exactly the runs where staging threw
     * or failed its digest - obscuring the real failure boundary with a false
     * one. The honest name is the pre-record it actually is; a later
     * {@code STEP_STAGEHOP_SENDING} is what implies staging passed, because the
     * coordinator refuses before the hop otherwise.
     */
    public static final String STEP_KSUD_STAGING = "EARLY_ROOT_KSUD_STAGING";
    /**
     * The hop is about to be sent, written before it is.
     *
     * Separate from {@link #STEP_STAGEHOP_SENT} because they are separate facts
     * (3.7): the coordinator reports {@code Phase.WAIT_CONTROLLER} only after
     * {@code StageHop.hopToNetworkStack()} has returned, so without this one a
     * process that died inside the hop would leave a trace ending at staging -
     * indistinguishable from a hop that was never attempted. The hop executes
     * our code in another security domain, so it is a privileged step, and
     * 3.6.1's rule applies to it: the record goes first, and a record that
     * cannot be written refuses the step.
     */
    public static final String STEP_STAGEHOP_SENDING = "EARLY_ROOT_STAGEHOP_SENDING";
    public static final String STEP_STAGEHOP_SENT = "EARLY_ROOT_STAGEHOP_SENT";
    public static final String STEP_CONTROLLER_RECEIVED = "EARLY_ROOT_CONTROLLER_RECEIVED";
    public static final String STEP_BEFORE_NATIVE = "EARLY_ROOT_BEFORE_NATIVE";
    public static final String STEP_NATIVE_RETURNED = "EARLY_ROOT_NATIVE_RETURNED";
    public static final String STEP_POST_ROOT_COMPLETE = "EARLY_ROOT_POST_ROOT_COMPLETE";
    public static final String STEP_SELINUX_ENFORCING = "EARLY_ROOT_SELINUX_ENFORCING";
    /** The run ended without the verdict above. Carries the coordinator's reason. */
    public static final String STEP_FAILED = "EARLY_ROOT_FAILED";
    /** A boundary refused. Carries the verdict code, so the log names which one. */
    public static final String STEP_REFUSED = "EARLY_ROOT_REFUSED";
    /**
     * {@code BOOT_COMPLETED} observed in the same boot, by the one component the
     * early path never touches.
     *
     * This is the comparison point the first milestone is stated in terms of:
     * "POST_ROOT_COMPLETE before BOOT_COMPLETED" needs both timestamps in one
     * boot's record, and the broadcast receiver is the only writer that is not
     * part of the thing being timed.
     */
    public static final String STEP_BOOT_COMPLETED_OBSERVED =
            "EARLY_ROOT_BOOT_COMPLETED_OBSERVED";

    private static final Set<String> STEPS = Set.of(
            STEP_JOB_ENTERED, STEP_READINESS_PASS, STEP_DISPATCHED,
            STEP_SERVICE_ENTERED, STEP_PREFLIGHT_PASS, STEP_COORDINATOR_ENTERED,
            STEP_KSUD_STAGING, STEP_STAGEHOP_SENDING, STEP_STAGEHOP_SENT,
            STEP_CONTROLLER_RECEIVED,
            STEP_BEFORE_NATIVE, STEP_NATIVE_RETURNED, STEP_POST_ROOT_COMPLETE,
            STEP_SELINUX_ENFORCING, STEP_FAILED, STEP_REFUSED,
            STEP_BOOT_COMPLETED_OBSERVED);

    /**
     * Upper bound on one boot's trace.
     *
     * The chain has fourteen steps and the job is one-shot, so a file that
     * outgrows this is not a long run - it is something re-entering, and an
     * append log that grows without bound in /data/system is a defect of its
     * own. Refusing the append is the fail-closed direction: the caller treats a
     * failed trace write as a refusal before any privileged step.
     */
    public static final int MAX_TRACE_STEPS = 64;

    private static final Set<String> ARM_KEYS = Set.of(
            "state", "armed_boot_id", "job_id", "namespace", "minimum_latency_ms",
            "schedule_result", "version_code", "version_name", "ksud_sha256",
            "device_fingerprint", "armed_elapsed_ms", "armed_wallclock_ms");

    private static final Set<String> JOURNAL_KEYS = Set.of(
            "boot_id", "phase", "attempts", "native_started");

    private EarlyRootPolicy() {}

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /**
     * The arm record: what the owner scheduled, and for which build.
     *
     * The build identity is stored IN the arm record rather than only compared
     * against the qualification, and that is not redundant. The qualification
     * answers "has the chain ever completed on this build"; the arm answers "did
     * the owner arm THIS build". An app update between the arming and the boot
     * leaves a pending job from a version of this code that no longer exists,
     * and the one thing it must not do is run the new one unattended at 15
     * seconds into a boot.
     */
    public static final class Arm {
        public final String armedBootId;
        public final int jobId;
        public final String namespace;
        public final long minimumLatencyMs;
        public final int versionCode;
        public final String versionName;
        public final String ksudSha256;
        public final String deviceFingerprint;

        private Arm(String armedBootId, int jobId, String namespace, long minimumLatencyMs,
                    int versionCode, String versionName, String ksudSha256,
                    String deviceFingerprint) {
            this.armedBootId = armedBootId;
            this.jobId = jobId;
            this.namespace = namespace;
            this.minimumLatencyMs = minimumLatencyMs;
            this.versionCode = versionCode;
            this.versionName = versionName;
            this.ksudSha256 = ksudSha256;
            this.deviceFingerprint = deviceFingerprint;
        }
    }

    /** One line of the durable per-boot trace. */
    public static final class TraceStep {
        public final String step;
        public final String bootId;
        public final long elapsedMs;
        public final String bootCompleted;
        public final String detail;

        private TraceStep(String step, String bootId, long elapsedMs,
                          String bootCompleted, String detail) {
            this.step = step;
            this.bootId = bootId;
            this.elapsedMs = elapsedMs;
            this.bootCompleted = bootCompleted;
            this.detail = detail;
        }
    }

    /** The journal for one boot: what the early path already did in it. */
    public static final class Journal {
        public final String bootId;
        public final String phase;
        public final int attempts;
        public final boolean nativeStarted;

        private Journal(String bootId, String phase, int attempts, boolean nativeStarted) {
            this.bootId = bootId;
            this.phase = phase;
            this.attempts = attempts;
            this.nativeStarted = nativeStarted;
        }
    }

    /** What the policy was asked about. Assembled by the caller, never trusted. */
    public static final class Inputs {
        public String armRecord;
        public String journalRecord;
        /**
         * The AUTO ROOT journal, if any, for this boot.
         *
         * The symmetric half of what {@code AutoRootPolicy} reads from the early
         * journal, and it is not decoration: without it the two triggers guard
         * each other in one direction only, which is 3.2 at the scale of the
         * whole feature.
         *
         * The reachable hole it closes: Auto Root is triggered by
         * {@code LOCKED_BOOT_COMPLETED}, which on this device arrives at
         * 17.6-19.7 s, and a persisted job restored late can be called back any
         * time inside the 120 s window. So Auto Root can reach transaction 5 and
         * record {@code STARTED} / {@code FAILED_LOCKED} FIRST. If its native
         * side then failed before {@code stage1} created {@code /dev/df}, the
         * marker probe answers a clean ENOENT, the coordinator's run guard has
         * been released, and the early journal is empty - every remaining
         * condition passes, and a second native transaction runs in a boot whose
         * page cache may already have been written.
         */
        public String autoRootJournalRecord;
        public String qualificationRecord;
        public String currentBootId;
        /** The job id the scheduler actually called back with. */
        public int callbackJobId;
        /** The namespace the scheduler actually called back in. */
        public String callbackNamespace;
        /** The namespace THIS runtime would have armed in. */
        public String expectedNamespace;
        /** One of the three {@code EarlyBootProbePolicy.NETWORKSTACK_*} states. */
        public String readinessState;
        /** Locally sampled ms since kernel boot. Negative refuses. */
        public long callbackElapsedMs = -1;
        /** One of {@code AutoRootPolicy.MARKER_*}. */
        public int markerState = AutoRootPolicy.MARKER_UNKNOWN;
        /** 1, 0, or -1 when /sys/fs/selinux/enforce could not be read. */
        public int liveSelinux = -1;
        public int versionCode;
        public String versionName;
        public String ksudSha256;
        public String deviceFingerprint;
    }

    /**
     * The answer.
     *
     * No {@code retryable}, unlike {@link AutoRootPolicy.Decision}, and the
     * absence is deliberate: there is exactly one callback. Nothing re-asks this
     * question in this boot, so a "wait and try again" verdict would describe a
     * loop that does not exist. A boundary that is not satisfied at the callback
     * is a refusal, and Auto Root's own trigger - which does have a retry budget
     * - still runs later in the same boot.
     */
    public static final class Decision {
        public final boolean allow;
        public final String code;
        public final String reason;

        private Decision(boolean allow, String code, String reason) {
            this.allow = allow;
            this.code = code;
            this.reason = reason;
        }
    }

    private static Decision refuse(String code, String reason) {
        return new Decision(false, code, reason);
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
        if (!new LinkedHashSet<>(out.keySet()).equals(keys)) return null;
        return out;
    }

    public static String formatArm(String bootId, int jobId, String namespace,
                                   long minimumLatencyMs, int scheduleResult,
                                   int versionCode, String versionName, String ksudSha256,
                                   String deviceFingerprint, long elapsedMs,
                                   long wallclockMs) {
        return "state=" + STATE_ARMED + "\n"
                + "armed_boot_id=" + bootId + "\n"
                + "job_id=" + jobId + "\n"
                + "namespace=" + namespace + "\n"
                + "minimum_latency_ms=" + minimumLatencyMs + "\n"
                + "schedule_result=" + scheduleResult + "\n"
                + "version_code=" + versionCode + "\n"
                + "version_name=" + versionName + "\n"
                + "ksud_sha256=" + ksudSha256 + "\n"
                + "device_fingerprint=" + deviceFingerprint + "\n"
                + "armed_elapsed_ms=" + elapsedMs + "\n"
                + "armed_wallclock_ms=" + wallclockMs + "\n";
    }

    /** null means malformed, unreadable, incomplete, or never actually scheduled. */
    public static Arm parseArm(String record) {
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return null;
        Map<String, String> values = parse(record, ARM_KEYS);
        if (values == null) return null;
        if (!STATE_ARMED.equals(values.get("state"))) return null;
        if (blank(values.get("armed_boot_id")) || blank(values.get("namespace"))) return null;
        if (blank(values.get("version_name")) || blank(values.get("ksud_sha256"))
                || blank(values.get("device_fingerprint"))) {
            return null;
        }
        try {
            int jobId = Integer.parseInt(values.get("job_id"));
            String namespace = values.get("namespace");
            long latency = Long.parseLong(values.get("minimum_latency_ms"));
            int scheduleResult = Integer.parseInt(values.get("schedule_result"));
            int versionCode = Integer.parseInt(values.get("version_code"));
            long armedElapsed = Long.parseLong(values.get("armed_elapsed_ms"));
            long armedWallclock = Long.parseLong(values.get("armed_wallclock_ms"));
            // A failed schedule is not an arming, and a failed clock reading at
            // arming time means the record cannot place itself in its own boot.
            if (latency <= 0 || scheduleResult != 1) return null;
            if (armedElapsed < 0 || armedWallclock < 0) return null;
            if (jobId != EXPECTED_JOB_ID) return null;
            // Exactly the two namespaces this feature can be armed in. Mutual
            // agreement between the record and the callback is not enough: uid
            // 1000 is shared, so a third namespace both agree on is
            // self-consistent evidence about a job nobody here scheduled.
            if (!EXPECTED_NAMESPACE.equals(namespace)
                    && !DEFAULT_UID_NAMESPACE.equals(namespace)) {
                return null;
            }
            return new Arm(values.get("armed_boot_id"), jobId, namespace, latency,
                    versionCode, values.get("version_name"), values.get("ksud_sha256"),
                    values.get("device_fingerprint"));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static String formatJournal(String bootId, String phase, int attempts,
                                       boolean nativeStarted) {
        return "boot_id=" + bootId + "\n"
                + "phase=" + phase + "\n"
                + "attempts=" + attempts + "\n"
                + "native_started=" + (nativeStarted ? 1 : 0) + "\n";
    }

    /**
     * Strict journal parse. An unknown phase or a {@code native_started} that is
     * neither 0 nor 1 refuses rather than falling through: a record this build
     * cannot account for may be describing a boot in which the page cache was
     * already written.
     */
    public static Journal parseJournal(String record) {
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return null;
        Map<String, String> values = parse(record, JOURNAL_KEYS);
        if (values == null) return null;
        String bootId = values.get("boot_id");
        String phase = values.get("phase");
        String nativeStarted = values.get("native_started");
        if (blank(bootId)) return null;
        if (!AutoRootPolicy.PHASE_PREFLIGHT.equals(phase)
                && !AutoRootPolicy.PHASE_STARTED.equals(phase)
                && !AutoRootPolicy.PHASE_COMPLETE.equals(phase)
                && !AutoRootPolicy.PHASE_FAILED_LOCKED.equals(phase)) {
            return null;
        }
        if (!"0".equals(nativeStarted) && !"1".equals(nativeStarted)) return null;
        int attempts;
        try {
            attempts = Integer.parseInt(values.get("attempts"));
        } catch (NumberFormatException e) {
            return null;
        }
        if (attempts < 0) return null;
        return new Journal(bootId, phase, attempts, "1".equals(nativeStarted));
    }

    /**
     * One trace line.
     *
     * Tab-separated fixed fields rather than this repository's usual
     * {@code key=value}, because {@code detail} carries free text: a
     * space-separated {@code key=value} line holding a value with spaces in it
     * cannot be strictly re-parsed, and a trace nobody can re-parse is not
     * evidence. The writer sanitises tabs and newlines out of every field, so
     * the field count is exact.
     */
    public static String formatTraceStep(String step, String bootId, long elapsedMs,
                                         String bootCompleted, String detail) {
        return clean(step) + "\t" + clean(bootId) + "\t" + elapsedMs + "\t"
                + clean(bootCompleted) + "\t" + clean(detail) + "\n";
    }

    private static String clean(String raw) {
        if (raw == null || raw.isEmpty()) return EarlyBootProbePolicy.UNKNOWN;
        String out = raw.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ').trim();
        return out.isEmpty() ? EarlyBootProbePolicy.UNKNOWN : out;
    }

    /** null for any line this build cannot fully account for. */
    public static TraceStep parseTraceLine(String line) {
        if (line == null) return null;
        String trimmed = line.trim();
        if (trimmed.isEmpty()) return null;
        String[] fields = trimmed.split("\t", -1);
        if (fields.length != 5) return null;
        if (!STEPS.contains(fields[0])) return null;
        if (fields[1].trim().isEmpty()) return null;
        long elapsed;
        try {
            elapsed = Long.parseLong(fields[2]);
        } catch (NumberFormatException e) {
            return null;
        }
        // A step whose clock could not be read orders nothing, and ordering is
        // the whole purpose of this file. It is refused rather than stored as a
        // negative that a later comparison could read as "very early".
        if (elapsed < 0) return null;
        return new TraceStep(fields[0], fields[1], elapsed, fields[3], fields[4]);
    }

    /** How many accountable steps a stored trace holds. */
    public static int traceStepCount(String record) {
        if (blank(record) || AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return 0;
        int count = 0;
        for (String line : record.split("\n", -1)) {
            if (parseTraceLine(line) != null) count++;
        }
        return count;
    }

    /**
     * Whether a stored trace is THIS boot's.
     *
     * Decided by the first accountable line, not by any line: a file whose
     * opening step belongs to an older boot is last boot's record, and appending
     * this boot's steps to it would produce one apparent sequence spanning two
     * boots - exactly what AGENTS.md 3.8 forbids. A record with no accountable
     * line at all belongs to no boot, so it is not this one's either.
     */
    public static boolean traceBelongsToBoot(String record, String bootId) {
        if (blank(bootId) || blank(record)) return false;
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return false;
        for (String line : record.split("\n", -1)) {
            TraceStep step = parseTraceLine(line);
            if (step != null) return bootId.equals(step.bootId);
        }
        return false;
    }

    /** Whether writing one more step would exceed the per-boot bound. */
    public static boolean traceHasRoom(String record) {
        return traceStepCount(record) < MAX_TRACE_STEPS;
    }

    /**
     * Everything that can be decided WITHOUT the reflection sweep.
     *
     * Split out so a device that was never armed - which is every device, almost
     * always - never pays for an AMS walk to be told so. It is not a second gate:
     * {@link #evaluate} runs this first and then adds what the sweep establishes,
     * so there is exactly one place where "may this proceed" is answered in full.
     * A caller may use this to skip work; it may never use it to proceed.
     */
    public static Decision evaluateBeforeReadiness(Inputs in) {
        if (in == null) return refuse(NO_BOOT_ID, "no inputs");
        if (blank(in.currentBootId)) {
            return refuse(NO_BOOT_ID, "current boot_id is unavailable; same-boot"
                    + " evidence could not be established");
        }
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.armRecord)) {
            return refuse(ARM_UNREADABLE,
                    "the early-root arm record exists but could not be read");
        }
        if (blank(in.armRecord)) {
            return refuse(ARM_NO_RECORD, "Early Integrated Root was not armed");
        }
        Arm arm = parseArm(in.armRecord);
        if (arm == null) {
            return refuse(ARM_MALFORMED, "the early-root arm record does not parse as"
                    + " an arming of this job");
        }
        /*
         * The full-boot requirement, and the reason a framework restart is
         * harmless: a restart keeps boot_id, so an arming can only ever take
         * effect in a LATER kernel boot. This is the same fact the probe records
         * as EARLY_JOB_FIRED_SAME_BOOT, and it is a refusal here rather than a
         * recorded observation because this path writes to the page cache.
         */
        if (in.currentBootId.equals(arm.armedBootId)) {
            return refuse(ARM_SAME_BOOT, "the callback fired in the boot the job was"
                    + " armed in; a full reboot is required before an early run");
        }
        /*
         * Bound to the scheduler, not only to our own file. Two fields agreeing
         * inside one record proves the record self-consistent; uid 1000 is shared
         * with every system component, so what ties the evidence to the scheduler
         * is the live callback naming the same job id and namespace.
         */
        if (in.callbackJobId != arm.jobId || in.callbackJobId != EXPECTED_JOB_ID) {
            return refuse(BINDING_MISMATCH, "the callback job id " + in.callbackJobId
                    + " is not the armed job " + arm.jobId);
        }
        /*
         * Three namespaces must agree, and they are three different facts.
         * `callbackNamespace` is what the scheduler called us back in;
         * `expectedNamespace` is what THIS runtime would arm in today, which an
         * OS upgrade across the API-34 namespace boundary can change under a
         * persisted job; `arm.namespace` is what was recorded. The refusal names
         * which comparison failed, because "namespace mismatch" with one value
         * printed is what makes a log unreadable at the moment it matters.
         */
        if (in.callbackNamespace == null || !in.callbackNamespace.equals(arm.namespace)) {
            return refuse(BINDING_MISMATCH, "the scheduler called back in namespace "
                    + in.callbackNamespace + ", not the armed namespace "
                    + arm.namespace);
        }
        if (in.expectedNamespace == null || !in.expectedNamespace.equals(arm.namespace)) {
            return refuse(BINDING_MISMATCH, "this runtime would arm in namespace "
                    + in.expectedNamespace + ", not the armed namespace "
                    + arm.namespace + "; the platform's namespace support changed"
                    + " under a persisted job");
        }
        /*
         * The build that was armed must be the build that runs. An app update
         * between the arming and the boot leaves a pending job belonging to code
         * that no longer exists, and the ksud digest is in here because the
         * daemon can be repinned without the app's version moving.
         */
        if (in.versionCode != arm.versionCode) {
            return refuse(BUILD_MISMATCH, "armed by versionCode " + arm.versionCode
                    + ", this build is " + in.versionCode);
        }
        if (in.versionName == null || !in.versionName.equals(arm.versionName)) {
            return refuse(BUILD_MISMATCH, "armed by version " + arm.versionName);
        }
        if (in.ksudSha256 == null || !in.ksudSha256.equals(arm.ksudSha256)) {
            return refuse(BUILD_MISMATCH, "armed against a different ksud digest");
        }
        if (in.deviceFingerprint == null
                || !in.deviceFingerprint.equals(arm.deviceFingerprint)) {
            return refuse(BUILD_MISMATCH, "armed on a different firmware build");
        }
        /*
         * And the chain must have completed here at least once, manually, on this
         * exact build. Early Root is strictly more dangerous than the button: it
         * writes to the page cache while the firmware's boot watchdog is still
         * deciding whether this boot completed. Discovering that the chain does
         * not work on this build is not a thing that should happen there.
         *
         * The qualification's opt_in flag is deliberately NOT consulted: that
         * flag is Auto Root's separate owner decision. Early Root's opt-in is the
         * arming, which is one-shot and bound to one boot.
         */
        if (!AutoRootPolicy.isQualified(in.qualificationRecord, in.versionCode,
                in.versionName, in.ksudSha256, in.deviceFingerprint)) {
            return refuse(NOT_QUALIFIED, "no Auto Root qualification for this exact"
                    + " build: a manual run must first end in verified same-boot"
                    + " POST_ROOT_COMPLETE");
        }
        if (in.callbackElapsedMs < 0) {
            return refuse(CLOCK_UNAVAILABLE, "time since kernel boot is unavailable;"
                    + " a callback that cannot be placed in the early window is"
                    + " refused");
        }
        if (in.callbackElapsedMs > EARLY_WINDOW_MS) {
            return refuse(PAST_WINDOW, "the callback arrived "
                    + (in.callbackElapsedMs / 1000) + "s after kernel boot, past the "
                    + (EARLY_WINDOW_MS / 1000) + "s early window; Auto Root's own"
                    + " trigger covers this boot");
        }
        /*
         * The journal. An unreadable one is the worst case rather than a blank
         * slate: it may say STARTED, i.e. the page cache was already written in
         * this boot.
         */
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.journalRecord)) {
            return refuse(JOURNAL_UNREADABLE, "the early-root journal exists but could"
                    + " not be read; refusing this boot");
        }
        if (!blank(in.journalRecord)) {
            Journal journal = parseJournal(in.journalRecord);
            if (journal == null) {
                return refuse(JOURNAL_MALFORMED, "the early-root journal is unreadable;"
                        + " it may have been written by a run that died mid-write");
            }
            if (in.currentBootId.equals(journal.bootId)) {
                /*
                 * One attempt per boot, and every shape of "already attempted"
                 * refuses the same way. There is one one-shot job, so a second
                 * entry in one boot is something re-entering - not a retry this
                 * policy owes anybody.
                 */
                return refuse(BOOT_SPENT, "the early path already reached phase "
                        + journal.phase + " in this boot (attempts="
                        + journal.attempts + ", native_started="
                        + (journal.nativeStarted ? 1 : 0)
                        + "); a hard reboot is the boundary");
            }
            // A journal naming another boot is last boot's record: it says
            // nothing about this one and must not lock it.
        }
        /*
         * And the other trigger's journal, for the same boot.
         *
         * Same rule, same exception, stated in the other direction: a
         * PREFLIGHT with native_started=0 means Auto Root polled readiness or
         * gave up before transaction 5, so provably nothing was written, and
         * refusing there would let a slow framework cost the early window for
         * no gain. Every other shape refuses - including FAILED_LOCKED with no
         * marker on disk, which is the interleaving this check exists for.
         *
         * Auto Root may still be mid-poll when this runs, so two callers can
         * both pass here and race; that is what DfrRootCoordinator's run guard
         * is for, and the loser gets a refusal with nothing written.
         */
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.autoRootJournalRecord)) {
            return refuse(AUTO_JOURNAL_UNREADABLE, "the Auto Root journal exists but"
                    + " could not be read; it may say STARTED, so this boot refuses");
        }
        if (!blank(in.autoRootJournalRecord)) {
            Journal auto = parseJournal(in.autoRootJournalRecord);
            if (auto == null) {
                return refuse(AUTO_JOURNAL_MALFORMED, "the Auto Root journal is"
                        + " unreadable; it may have been written by a run that died"
                        + " mid-write");
            }
            if (in.currentBootId.equals(auto.bootId)
                    && (!AutoRootPolicy.PHASE_PREFLIGHT.equals(auto.phase)
                        || auto.nativeStarted)) {
                return refuse(AUTO_BOOT_SPENT, "Auto Root already reached phase "
                        + auto.phase + " in this boot (native_started="
                        + (auto.nativeStarted ? 1 : 0) + "); the page cache may"
                        + " already carry its writes, with or without a /dev/df"
                        + " marker");
            }
        }
        return new Decision(true, ALLOW, "EARLY_ROOT_PREFLIGHT=PASS (pre-readiness)");
    }

    /**
     * May the early chain run now?
     *
     * The complete gate. Every caller - the job callback and the service it
     * dispatches - calls this one, because a gate enforced at one of two entry
     * points is the defect AGENTS.md 3.2 describes for the native stages.
     */
    public static Decision evaluate(Inputs in) {
        Decision durable = evaluateBeforeReadiness(in);
        if (!durable.allow) return durable;
        /*
         * Observed state, in the order that puts the cheapest refusal first. The
         * marker check is the same one the button and Auto Root make, and it is
         * here for the same reason: /dev/df or any dfm marker means a run already
         * armed hooks in this boot, and only a hard reboot clears them.
         */
        if (in.markerState == AutoRootPolicy.MARKER_PRESENT) {
            return refuse(MARKER_PRESENT, "/dev/df or a stage marker is already"
                    + " present; only a hard reboot clears armed hooks");
        }
        if (in.markerState != AutoRootPolicy.MARKER_ABSENT) {
            // Not ENOENT, so the probe failed rather than finding nothing. An
            // unreadable /dev is not an empty /dev.
            return refuse(MARKER_UNKNOWN, "whether /dev/df or a stage marker exists"
                    + " could not be determined; refusing rather than assuming a"
                    + " clean boot");
        }
        if (in.liveSelinux != 1) {
            return refuse(SELINUX_NOT_ENFORCING, "initial /sys/fs/selinux/enforce is "
                    + in.liveSelinux + ", expected 1 (unreadable reads as -1 and also"
                    + " refuses)");
        }
        /*
         * What replaces sys.boot_completed, and the one place this policy is
         * stricter than Auto Root rather than laxer.
         *
         * Auto Root treats a NetworkStack process it cannot see as UNKNOWN and
         * proceeds, because the hop performs its own authoritative AMS lookup
         * afterwards and nothing destructive has happened yet. That reasoning is
         * sound there and wrong here: in the early window the question is not
         * "can we see the process" but "is the framework far enough along to
         * serve the hop at all", and the four readiness components ARE that
         * question. PARTIAL means at least one of them was not resolvable, which
         * in this window is indistinguishable from "too early" - so it refuses,
         * and the boot is left to Auto Root's own trigger, which has a retry
         * budget this one-shot callback does not.
         */
        if (!EarlyBootProbePolicy.NETWORKSTACK_READY.equals(in.readinessState)) {
            return refuse(READINESS_REFUSED, "StageHop readiness is "
                    + in.readinessState + ", not "
                    + EarlyBootProbePolicy.NETWORKSTACK_READY
                    + "; an early window the hop cannot use is not an early window");
        }
        return new Decision(true, ALLOW, "EARLY_ROOT_PREFLIGHT=PASS");
    }

    /**
     * The phase a finished run is recorded under.
     *
     * The same R1 correction {@link DfrAutoRootService} carries, restated where
     * it can be tested: {@code nativeStarted == false} means transaction 5 was
     * never issued, so provably nothing was written - no marker, no patched
     * libc, no staged handoff - and the states that make a retry dangerous
     * cannot exist. Recording that as FAILED_LOCKED would spend a boot on a
     * refusal that changed nothing.
     *
     * It still consumes this boot's single attempt, because
     * {@link #MAX_ATTEMPTS_PER_BOOT} is 1 and the job is one-shot. The
     * distinction it preserves is for the NEXT boot's reader and for Auto Root,
     * which may legitimately try later in this one.
     */
    public static String terminalPhase(boolean success, boolean nativeStarted) {
        if (success) return AutoRootPolicy.PHASE_COMPLETE;
        return nativeStarted
                ? AutoRootPolicy.PHASE_FAILED_LOCKED
                : AutoRootPolicy.PHASE_PREFLIGHT;
    }
}
