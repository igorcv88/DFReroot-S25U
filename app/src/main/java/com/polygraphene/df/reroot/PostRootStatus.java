package com.polygraphene.df.reroot;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** Pure parser for the DFR-only, same-boot post-root completion record. */
public final class PostRootStatus {
    public static final String PATH = "/data/system/dfreroot-post-root";
    public static final int EXPECTED_KSU_VERSION = 32601;
    public static final int EXPECTED_UAPI_VERSION = 2;

    private static final Set<String> KEYS = Set.of(
            "state", "boot_id", "ksu_version", "uapi_version", "runtime_mode", "selinux");

    private PostRootStatus() {}

    public static final class Verdict {
        public final boolean complete;
        public final String reason;

        private Verdict(boolean complete, String reason) {
            this.complete = complete;
            this.reason = reason;
        }
    }

    private static Verdict fail(String reason) {
        return new Verdict(false, reason);
    }

    public static Verdict evaluate(String record, String currentBootId, int liveSelinux) {
        if (record == null || record.isBlank()) return fail("completion record absent or empty");
        if (currentBootId == null || currentBootId.isBlank()) return fail("current boot_id unavailable");

        Map<String, String> values = new HashMap<>();
        for (String raw : record.split("\\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int separator = line.indexOf('=');
            if (separator <= 0 || separator == line.length() - 1) {
                return fail("malformed status line: " + line);
            }
            String key = line.substring(0, separator);
            String value = line.substring(separator + 1);
            if (!KEYS.contains(key)) return fail("unknown status key: " + key);
            if (values.putIfAbsent(key, value) != null) return fail("duplicate status key: " + key);
        }
        if (!values.keySet().equals(KEYS)) return fail("completion record is missing required fields");
        if (!"POST_ROOT_COMPLETE".equals(values.get("state"))) return fail("state is not complete");
        if (!currentBootId.equals(values.get("boot_id"))) return fail("stale boot_id");
        if (!Integer.toString(EXPECTED_KSU_VERSION).equals(values.get("ksu_version"))) {
            return fail("unexpected KernelSU version");
        }
        if (!Integer.toString(EXPECTED_UAPI_VERSION).equals(values.get("uapi_version"))) {
            return fail("unexpected KernelSU UAPI version");
        }
        if (!"late-load".equals(values.get("runtime_mode"))) return fail("runtime mode is not late-load");
        if (!"1".equals(values.get("selinux"))) return fail("recorded SELinux state is not 1");
        if (liveSelinux != 1) return fail("live /sys/fs/selinux/enforce is not 1");
        return new Verdict(true, "same-boot KernelSU + SELinux post-root contract complete");
    }
}
