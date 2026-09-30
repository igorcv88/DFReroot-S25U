package com.polygraphene.df.reroot;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Pure, strict policy for the observation-only persisted JobScheduler probe. */
public final class EarlyBootProbePolicy {
    public static final String STATE_SCHEDULED = "EARLY_JOB_SCHEDULED";
    public static final String STATE_FIRED = "EARLY_JOB_FIRED";
    public static final String STATE_FIRED_SAME_BOOT = "EARLY_JOB_FIRED_SAME_BOOT";
    public static final String STATE_FIRED_NEW_BOOT = "EARLY_JOB_FIRED_NEW_BOOT";
    public static final String PRE_LOCKED = "EARLY_JOB_PRE_LOCKED_BOOT";
    public static final String POST_LOCKED = "EARLY_JOB_POST_LOCKED_BOOT";
    public static final String LOCKED_PENDING = "EARLY_JOB_LOCKED_BOOT_PENDING";
    public static final String LOCKED_UNKNOWN = "EARLY_JOB_LOCKED_BOOT_UNKNOWN";

    /** Written when a monotonic read failed. Never parses back into a number. */
    public static final String UNKNOWN = "UNKNOWN";

    /** One identity and vocabulary for the persisted DFR probe across Java/Kotlin. */
    public static final int EXPECTED_JOB_ID = 0x44465245; // "DFRE"
    public static final String EXPECTED_NAMESPACE = "dfr-early-boot-probe";
    public static final String DEFAULT_UID_NAMESPACE = "DEFAULT_UID_NAMESPACE";

    public static final String SIGNAL_PASS = "PASS";
    public static final String SIGNAL_FAIL = "FAIL";
    public static final String NETWORKSTACK_READY = "NETWORKSTACK_READY";
    public static final String NETWORKSTACK_PARTIAL = "NETWORKSTACK_PARTIAL";
    public static final String NETWORKSTACK_NOT_READY = "NETWORKSTACK_NOT_READY";
    public static final String SAME_BOOT_TRUE = "1";
    public static final String SAME_BOOT_FALSE = "0";

    public static final String CALLBACK_ENTERED = "EARLY_JOB_CALLBACK_ENTERED";
    public static final String CALLBACK_STOPPED = "EARLY_JOB_CALLBACK_STOPPED";
    public static final String STOP_BEFORE_ARM_READ = "before_arm_read";
    public static final String STOP_BEFORE_READINESS = "before_readiness";
    public static final String STOP_AFTER_READINESS = "after_readiness";
    public static final String STOP_BEFORE_MARKER = "before_marker";

    private static final Set<String> ARM_KEYS = Set.of(
            "state", "armed_boot_id", "job_id", "namespace",
            "minimum_latency_ms", "schedule_result", "scheduled_elapsed_ms",
            "scheduled_wallclock_ms");

    /*
     * The exact key set the callback writes. It is strict in both directions: a
     * key missing here and a key present but unexpected are both refusals,
     * because this record is what would promote DFR_PERSISTED_JOB_EARLY_CALLBACK
     * and a record nobody can fully account for is not evidence of anything.
     */
    private static final Set<String> PROBE_KEYS = Set.of(
            "state", "fire_state", "locked_boot_state", "networkstack_state",
            "armed_boot_id", "fired_boot_id", "same_boot", "job_id",
            "namespace", "callback_namespace", "namespace_binding",
            "callback_elapsed_ms", "readiness_elapsed_ms", "marker_write_elapsed_ms",
            "callback_wallclock_ms", "stopped", "pid", "ppid", "uid", "euid", "selinux",
            "sys_boot_completed", "user_unlocked", "bootanim_exit",
            "networkstack_proc", "ams_process_record", "application_thread",
            "schedule_receiver_12");

    private static final Set<String> LOCKED_KEYS = Set.of("boot_id", "elapsed_ms");

    private static final Set<String> CALLBACK_ENTERED_KEYS = Set.of(
            "state", "fired_boot_id", "job_id", "callback_namespace",
            "callback_elapsed_ms", "callback_wallclock_ms");

    private static final Set<String> CALLBACK_STOPPED_KEYS = Set.of(
            "state", "fired_boot_id", "job_id", "stopped_at", "callback_elapsed_ms");

    private static final Set<String> FIRE_STATES = Set.of(
            "EARLY_JOB_NOT_ARMED", STATE_FIRED_SAME_BOOT, STATE_FIRED_NEW_BOOT);

    private static final Set<String> LOCKED_STATES = Set.of(
            PRE_LOCKED, POST_LOCKED, LOCKED_PENDING, LOCKED_UNKNOWN);

    /*
     * The remaining fields are validated too, and not for tidiness. PRE/POST
     * needs only four of them, but DFR_JOB_STAGEHOP_READY would be promoted
     * from exactly the ones below - the four readiness signals and the state
     * they roll up into. A field that decides a gate later must be refused
     * now when it holds something nobody wrote, or the strictness stops
     * exactly where the next verdict starts.
     */
    private static final Set<String> READINESS_STATES = Set.of(
            NETWORKSTACK_READY, NETWORKSTACK_PARTIAL, NETWORKSTACK_NOT_READY);

    private static final Set<String> SIGNALS = Set.of(SIGNAL_PASS, SIGNAL_FAIL, UNKNOWN);

    private static final Set<String> BINDINGS = Set.of("PASS", "FAIL");

    private static final Set<String> SAME_BOOT = Set.of("0", "1", UNKNOWN);

    private static final Set<String> BOOLEANS = Set.of("0", "1");

    /** Fields that are a monotonic reading or an explicit UNKNOWN, never junk. */
    private static final Set<String> OPTIONAL_TIMES = Set.of(
            "callback_elapsed_ms", "readiness_elapsed_ms", "marker_write_elapsed_ms",
            "callback_wallclock_ms");

    /** Fields carrying one of the four readiness signals. */
    private static final Set<String> SIGNAL_FIELDS = Set.of(
            "networkstack_proc", "ams_process_record", "application_thread",
            "schedule_receiver_12");

    private static final Set<String> STOP_BOUNDARIES = Set.of(
            STOP_BEFORE_ARM_READ, STOP_BEFORE_READINESS,
            STOP_AFTER_READINESS, STOP_BEFORE_MARKER);

    private EarlyBootProbePolicy() {}

    public static final class Arm {
        public final String armedBootId;
        public final int jobId;
        public final String namespace;
        public final long minimumLatencyMs;

        private Arm(String armedBootId, int jobId, String namespace, long minimumLatencyMs) {
            this.armedBootId = armedBootId;
            this.jobId = jobId;
            this.namespace = namespace;
            this.minimumLatencyMs = minimumLatencyMs;
        }
    }

    /** A fully accounted-for callback record. Any deviation parses to null. */
    public static final class Probe {
        public final String firedBootId;
        public final String fireState;
        public final String lockedBootState;
        public final long callbackElapsedMs;

        private Probe(String firedBootId, String fireState, String lockedBootState,
                      long callbackElapsedMs) {
            this.firedBootId = firedBootId;
            this.fireState = fireState;
            this.lockedBootState = lockedBootState;
            this.callbackElapsedMs = callbackElapsedMs;
        }
    }

    /** Strictly parsed durable evidence that JobScheduler entered the callback. */
    public static final class Callback {
        public final String state;
        public final String firedBootId;
        public final int jobId;
        public final long callbackElapsedMs;
        public final String stoppedAt;

        private Callback(String state, String firedBootId, int jobId,
                         long callbackElapsedMs, String stoppedAt) {
            this.state = state;
            this.firedBootId = firedBootId;
            this.jobId = jobId;
            this.callbackElapsedMs = callbackElapsedMs;
            this.stoppedAt = stoppedAt;
        }
    }

    /** The first LOCKED_BOOT_COMPLETED of one boot. */
    public static final class Locked {
        public final String bootId;
        public final long elapsedMs;

        private Locked(String bootId, long elapsedMs) {
            this.bootId = bootId;
            this.elapsedMs = elapsedMs;
        }
    }

    /** null means malformed, unknown, duplicated, incomplete, or unscheduled. */
    public static Arm parseArm(String record) {
        Map<String, String> values = strictFields(record, ARM_KEYS);
        if (values == null) return null;
        if (!STATE_SCHEDULED.equals(values.get("state"))) return null;
        String bootId = values.get("armed_boot_id");
        String namespace = values.get("namespace");
        if (bootId.trim().isEmpty() || namespace.trim().isEmpty()) return null;
        try {
            int jobId = Integer.parseInt(values.get("job_id"));
            long latency = Long.parseLong(values.get("minimum_latency_ms"));
            int scheduleResult = Integer.parseInt(values.get("schedule_result"));
            Long.parseLong(values.get("scheduled_elapsed_ms"));
            Long.parseLong(values.get("scheduled_wallclock_ms"));
            if (latency <= 0 || scheduleResult != 1) return null;
            return new Arm(bootId, jobId, namespace, latency);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Strict parse of the callback record.
     *
     * finalizeLockedBoot() rewrites one field of this record and that rewrite is
     * what promotes the whole experiment, so the record it rewrites is held to
     * the same standard as the arm record: unknown key, duplicate key, missing
     * key, an unrecognised enum value or a malformed timestamp all refuse.
     * A callback_elapsed_ms of UNKNOWN parses, but only into a negative value
     * that can never win a comparison - a clock that could not be read is not a
     * timestamp that happens to be early.
     */
    public static Probe parseProbe(String record) {
        Map<String, String> values = strictFields(record, PROBE_KEYS);
        if (values == null) return null;
        if (!STATE_FIRED.equals(values.get("state"))) return null;

        String fireState = values.get("fire_state");
        String lockedState = values.get("locked_boot_state");
        String firedBootId = values.get("fired_boot_id");
        String armedBootId = values.get("armed_boot_id");
        String sameBoot = values.get("same_boot");
        String binding = values.get("namespace_binding");
        String namespace = values.get("namespace");
        String callbackNamespace = values.get("callback_namespace");

        if (!FIRE_STATES.contains(fireState) || !LOCKED_STATES.contains(lockedState)) return null;
        if (firedBootId.trim().isEmpty()) return null;
        if (!READINESS_STATES.contains(values.get("networkstack_state"))) return null;
        if (!BINDINGS.contains(binding)) return null;
        if (!SAME_BOOT.contains(sameBoot)) return null;
        if (!BOOLEANS.contains(values.get("stopped"))) return null;
        for (String field : SIGNAL_FIELDS) {
            if (!SIGNALS.contains(values.get(field))) return null;
        }

        int jobId;
        try {
            jobId = Integer.parseInt(values.get("job_id"));
        } catch (NumberFormatException e) {
            return null;
        }
        if (jobId != EXPECTED_JOB_ID) return null;

        long callbackElapsed = parseOptionalLong(values.get("callback_elapsed_ms"));
        long readinessElapsed = parseOptionalLong(values.get("readiness_elapsed_ms"));
        long markerElapsed = parseOptionalLong(values.get("marker_write_elapsed_ms"));
        long callbackWallclock = parseOptionalLong(values.get("callback_wallclock_ms"));
        if (callbackElapsed == Long.MIN_VALUE || readinessElapsed == Long.MIN_VALUE
                || markerElapsed == Long.MIN_VALUE || callbackWallclock == Long.MIN_VALUE) {
            return null;
        }
        if (callbackElapsed >= 0 && readinessElapsed >= 0
                && callbackElapsed > readinessElapsed) return null;
        if (readinessElapsed >= 0 && markerElapsed >= 0
                && readinessElapsed > markerElapsed) return null;

        String expectedReadiness = readinessState(
                values.get("networkstack_proc"), values.get("ams_process_record"),
                values.get("application_thread"), values.get("schedule_receiver_12"));
        if (!expectedReadiness.equals(values.get("networkstack_state"))) return null;

        if (STATE_FIRED_SAME_BOOT.equals(fireState)) {
            if (!SAME_BOOT_TRUE.equals(sameBoot) || !armedBootId.equals(firedBootId)) return null;
            if (!SIGNAL_PASS.equals(binding) || !namespace.equals(callbackNamespace)) return null;
        } else if (STATE_FIRED_NEW_BOOT.equals(fireState)) {
            if (!SAME_BOOT_FALSE.equals(sameBoot) || UNKNOWN.equals(armedBootId)
                    || armedBootId.equals(firedBootId)) return null;
            if (!SIGNAL_PASS.equals(binding) || !namespace.equals(callbackNamespace)) return null;
        } else {
            if (!UNKNOWN.equals(sameBoot) || !UNKNOWN.equals(armedBootId)) return null;
        }
        return new Probe(firedBootId, fireState, lockedState, callbackElapsed);
    }

    /** Strict parser for the pre-readiness callback breadcrumb. */
    public static Callback parseCallback(String record) {
        Map<String, String> entered = strictFields(record, CALLBACK_ENTERED_KEYS);
        if (entered != null && CALLBACK_ENTERED.equals(entered.get("state"))) {
            int jobId = parseExpectedJobId(entered.get("job_id"));
            long callbackElapsed = parseOptionalLong(entered.get("callback_elapsed_ms"));
            long callbackWallclock = parseOptionalLong(entered.get("callback_wallclock_ms"));
            if (jobId < 0 || callbackElapsed == Long.MIN_VALUE
                    || callbackWallclock == Long.MIN_VALUE) return null;
            return new Callback(CALLBACK_ENTERED, entered.get("fired_boot_id"),
                    jobId, callbackElapsed, null);
        }

        Map<String, String> stopped = strictFields(record, CALLBACK_STOPPED_KEYS);
        if (stopped != null && CALLBACK_STOPPED.equals(stopped.get("state"))) {
            int jobId = parseExpectedJobId(stopped.get("job_id"));
            long callbackElapsed = parseOptionalLong(stopped.get("callback_elapsed_ms"));
            String boundary = stopped.get("stopped_at");
            if (jobId < 0 || callbackElapsed == Long.MIN_VALUE
                    || !STOP_BOUNDARIES.contains(boundary)) return null;
            return new Callback(CALLBACK_STOPPED, stopped.get("fired_boot_id"),
                    jobId, callbackElapsed, boundary);
        }
        return null;
    }

    /**
     * Whether THIS boot still needs its first LOCKED_BOOT_COMPLETED timestamp.
     *
     * A callback/probe from this same boot still needs the marker until the
     * probe has a final verdict. A callback/probe from an older boot is a spent
     * cycle and the current boot's marker cannot finalize it. Malformed or
     * unreadable evidence never stands in for "spent".
     */
    public static boolean needsLockedBootMarker(String probeRecord, String callbackRecord,
                                                String currentBootId) {
        if (currentBootId == null || currentBootId.trim().isEmpty()) return false;

        Probe probe = parseProbe(probeRecord);
        if (probe != null) {
            if (!LOCKED_PENDING.equals(probe.lockedBootState)) return false;
            return currentBootId.equals(probe.firedBootId);
        }

        Callback callback = parseCallback(callbackRecord);
        if (callback != null) {
            if (UNKNOWN.equals(callback.firedBootId)) return false;
            return currentBootId.equals(callback.firedBootId);
        }

        // No valid callback/probe says the one-shot fired. The persisted job may
        // still be waiting, so preserve the timestamp rather than assume spent.
        return true;
    }

    /** The one readiness roll-up used by both StageHop and the evidence parser. */
    public static String readinessState(String proc, String processRecord,
                                        String applicationThread, String scheduleReceiver12) {
        if (SIGNAL_PASS.equals(proc) && SIGNAL_PASS.equals(processRecord)
                && SIGNAL_PASS.equals(applicationThread)
                && SIGNAL_PASS.equals(scheduleReceiver12)) {
            return NETWORKSTACK_READY;
        }
        if (SIGNAL_FAIL.equals(proc) || SIGNAL_FAIL.equals(processRecord)) {
            return NETWORKSTACK_NOT_READY;
        }
        return NETWORKSTACK_PARTIAL;
    }

    private static int parseExpectedJobId(String raw) {
        try {
            int jobId = Integer.parseInt(raw);
            return jobId == EXPECTED_JOB_ID ? jobId : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Strict parse of the locked-boot marker. null means "no usable evidence". */
    public static Locked parseLockedBoot(String record) {
        Map<String, String> values = strictFields(record, LOCKED_KEYS);
        if (values == null) return null;
        String bootId = values.get("boot_id");
        if (bootId.trim().isEmpty()) return null;
        long elapsed;
        try {
            elapsed = Long.parseLong(values.get("elapsed_ms"));
        } catch (NumberFormatException e) {
            return null;
        }
        // A marker whose timestamp is not a real monotonic reading orders
        // nothing. Refusing it here is what keeps a failed clock from being
        // read back later as "the locked boot happened at -1, so the job was
        // earlier".
        if (elapsed < 0) return null;
        return new Locked(bootId, elapsed);
    }

    public static String formatLockedBoot(String bootId, long elapsedMs) {
        return "boot_id=" + bootId + "\nelapsed_ms=" + elapsedMs + "\n";
    }

    /**
     * Decide what the locked-boot marker should hold after one broadcast.
     *
     * A framework restart re-delivers LOCKED_BOOT_COMPLETED within the same
     * boot_id. Letting the later delivery win would move the comparison point
     * forward and could turn a job that ran after the real locked boot into an
     * apparent PRE_LOCKED. So within one boot the FIRST valid timestamp is
     * immutable; only a different boot replaces the record.
     *
     * @return the body to write, or null to keep what is already stored.
     */
    public static String mergeLockedBoot(String existing, String bootId, long elapsedMs) {
        if (bootId == null || bootId.trim().isEmpty() || elapsedMs < 0) return null;
        Locked stored = existing == null ? null : parseLockedBoot(existing);
        if (stored != null && stored.bootId.equals(bootId) && stored.elapsedMs <= elapsedMs) {
            return null;
        }
        return formatLockedBoot(bootId, elapsedMs);
    }

    public static String fireState(Arm arm, String firedBootId) {
        if (arm == null || firedBootId == null || firedBootId.trim().isEmpty()) {
            return "EARLY_JOB_NOT_ARMED";
        }
        return arm.armedBootId.equals(firedBootId)
                ? STATE_FIRED_SAME_BOOT : STATE_FIRED_NEW_BOOT;
    }

    /** Same-boot execution is never promoted to an early-trigger result. */
    public static String lockedBootState(Arm arm, String firedBootId,
                                         String lockedBootId, long lockedElapsedMs,
                                         long firedElapsedMs) {
        if (!STATE_FIRED_NEW_BOOT.equals(fireState(arm, firedBootId))) {
            return LOCKED_UNKNOWN;
        }
        // No monotonic reading for our own callback means no ordering is
        // possible in this boot, now or later. PENDING would invite the
        // receiver to finalize it from one half of a comparison.
        if (firedElapsedMs < 0) return LOCKED_UNKNOWN;
        if (firedBootId.equals(lockedBootId) && lockedElapsedMs >= 0) {
            return firedElapsedMs < lockedElapsedMs ? PRE_LOCKED : POST_LOCKED;
        }
        // Absence at callback time is a candidate, not final proof: the receiver
        // may later persist its timestamp, or its write may fail. The receiver
        // finalizes this to PRE_LOCKED by comparing the two elapsed timestamps.
        if (lockedBootId == null) return LOCKED_PENDING;
        if (lockedBootId.isEmpty()) return LOCKED_UNKNOWN;
        if (!firedBootId.equals(lockedBootId)) return LOCKED_PENDING;
        return LOCKED_UNKNOWN;
    }

    /**
     * The verdict a late locked-boot timestamp gives an already-written probe.
     *
     * Only a record still reading LOCKED_PENDING is finalized. That makes the
     * operation idempotent and monotone no matter which of the two workers - the
     * job callback or the receiver - gets there first, and it means a verdict
     * already computed from both timestamps can never be rewritten by a second
     * pass over the same numbers.
     *
     * @return the new locked_boot_state, or null when nothing should change.
     */
    public static String finalizeState(Probe probe, String lockedBootId, long lockedElapsedMs) {
        if (probe == null) return null;
        if (!LOCKED_PENDING.equals(probe.lockedBootState)) return null;
        if (!STATE_FIRED_NEW_BOOT.equals(probe.fireState)) return null;
        if (lockedBootId == null || !probe.firedBootId.equals(lockedBootId)) return null;
        if (lockedElapsedMs < 0 || probe.callbackElapsedMs < 0) return null;
        return probe.callbackElapsedMs < lockedElapsedMs ? PRE_LOCKED : POST_LOCKED;
    }

    /** Rewrite exactly the locked_boot_state line, leaving every other byte alone. */
    public static String withLockedBootState(String record, String state) {
        StringBuilder out = new StringBuilder();
        for (String line : record.split("\\n", -1)) {
            if (line.isEmpty()) continue;
            out.append(line.startsWith("locked_boot_state=")
                    ? "locked_boot_state=" + state : line).append('\n');
        }
        return out.toString();
    }

    public static String formatArm(String bootId, int jobId, String namespace,
                                   long minimumLatencyMs, int scheduleResult, long elapsedMs,
                                   long wallclockMs) {
        return "state=" + STATE_SCHEDULED + "\n"
                + "armed_boot_id=" + bootId + "\n"
                + "job_id=" + jobId + "\n"
                + "namespace=" + namespace + "\n"
                + "minimum_latency_ms=" + minimumLatencyMs + "\n"
                + "schedule_result=" + scheduleResult + "\n"
                + "scheduled_elapsed_ms=" + elapsedMs + "\n"
                + "scheduled_wallclock_ms=" + wallclockMs + "\n";
    }

    /**
     * key=value lines, every key in {@code keys} present exactly once and no key
     * outside it. Returns null on any deviation.
     */
    private static Map<String, String> strictFields(String record, Set<String> keys) {
        if (record == null || record.trim().isEmpty()) return null;
        Map<String, String> values = new HashMap<>();
        for (String raw : record.split("\\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int separator = line.indexOf('=');
            if (separator <= 0 || separator == line.length() - 1) return null;
            String key = line.substring(0, separator);
            if (!keys.contains(key)) return null;
            if (values.putIfAbsent(key, line.substring(separator + 1)) != null) return null;
        }
        if (!new LinkedHashSet<>(values.keySet()).equals(keys)) return null;
        return values;
    }

    /**
     * -1 for a recorded UNKNOWN, the value for a non-negative number,
     * MIN_VALUE for anything else.
     *
     * A numeric negative is not a second spelling of UNKNOWN. The writer emits
     * either a real monotonic reading or the literal token, so a record
     * holding `-1` is one nobody in this codebase wrote - a corrupted or
     * externally edited file - and a fail-closed parser refuses what it cannot
     * account for rather than reading it as missing evidence.
     */
    private static long parseOptionalLong(String raw) {
        if (UNKNOWN.equals(raw)) return -1L;
        try {
            long value = Long.parseLong(raw);
            return value < 0 ? Long.MIN_VALUE : value;
        } catch (NumberFormatException e) {
            return Long.MIN_VALUE;
        }
    }
}
