package com.polygraphene.df.reroot;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** Pure, strict policy for the observation-only persisted JobScheduler probe. */
public final class EarlyBootProbePolicy {
    public static final String STATE_SCHEDULED = "EARLY_JOB_SCHEDULED";
    public static final String STATE_FIRED_SAME_BOOT = "EARLY_JOB_FIRED_SAME_BOOT";
    public static final String STATE_FIRED_NEW_BOOT = "EARLY_JOB_FIRED_NEW_BOOT";
    public static final String PRE_LOCKED = "EARLY_JOB_PRE_LOCKED_BOOT";
    public static final String POST_LOCKED = "EARLY_JOB_POST_LOCKED_BOOT";
    public static final String LOCKED_PENDING = "EARLY_JOB_LOCKED_BOOT_PENDING";
    public static final String LOCKED_UNKNOWN = "EARLY_JOB_LOCKED_BOOT_UNKNOWN";

    private static final Set<String> ARM_KEYS = Set.of(
            "state", "armed_boot_id", "job_id", "namespace",
            "minimum_latency_ms", "schedule_result", "scheduled_elapsed_ms",
            "scheduled_wallclock_ms");

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

    /** null means malformed, unknown, duplicated, incomplete, or unscheduled. */
    public static Arm parseArm(String record) {
        if (record == null || record.trim().isEmpty()) return null;
        Map<String, String> values = new HashMap<>();
        for (String raw : record.split("\\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int separator = line.indexOf('=');
            if (separator <= 0 || separator == line.length() - 1) return null;
            String key = line.substring(0, separator);
            if (!ARM_KEYS.contains(key)) return null;
            if (values.putIfAbsent(key, line.substring(separator + 1)) != null) return null;
        }
        if (!values.keySet().equals(ARM_KEYS)) return null;
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
        if (firedBootId.equals(lockedBootId) && lockedElapsedMs >= 0 && firedElapsedMs >= 0) {
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
}
