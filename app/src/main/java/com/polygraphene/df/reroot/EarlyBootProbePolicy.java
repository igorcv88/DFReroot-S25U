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
            "NETWORKSTACK_READY", "NETWORKSTACK_PARTIAL", "NETWORKSTACK_NOT_READY");

    private static final Set<String> SIGNALS = Set.of("PASS", "FAIL", UNKNOWN);

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
        if (!FIRE_STATES.contains(fireState)) return null;
        if (!LOCKED_STATES.contains(lockedState)) return null;
        String firedBootId = values.get("fired_boot_id");
        if (firedBootId.trim().isEmpty()) return null;
        if (!READINESS_STATES.contains(values.get("networkstack_state"))) return null;
        if (!BINDINGS.contains(values.get("namespace_binding"))) return null;
        if (!SAME_BOOT.contains(values.get("same_boot"))) return null;
        if (!BOOLEANS.contains(values.get("stopped"))) return null;
        for (String field : SIGNAL_FIELDS) {
            if (!SIGNALS.contains(values.get(field))) return null;
        }
        try {
            Integer.parseInt(values.get("job_id"));
        } catch (NumberFormatException e) {
            return null;
        }
        for (String field : OPTIONAL_TIMES) {
            long value = parseOptionalLong(values.get(field));
            // MIN_VALUE is garbage; any other negative is a number that is not
            // a monotonic reading, and UNKNOWN is the only way to say "absent".
            if (value == Long.MIN_VALUE || value < -1L) return null;
        }
        long callbackElapsed = parseOptionalLong(values.get("callback_elapsed_ms"));
        return new Probe(firedBootId, fireState, lockedState, callbackElapsed);
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

    /** -1 for a recorded UNKNOWN, the value for a number, MIN_VALUE for garbage. */
    private static long parseOptionalLong(String raw) {
        if (UNKNOWN.equals(raw)) return -1L;
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException e) {
            return Long.MIN_VALUE;
        }
    }
}
