package com.polygraphene.df.reroot;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** Pure parser for the DFR-only, same-boot post-root completion record. */
public final class PostRootStatus {
    public static final String PATH = "/data/system/dfreroot-post-root";
    public static final int EXPECTED_KSU_VERSION = 32601;
    public static final int EXPECTED_UAPI_VERSION = 2;

    /**
     * The paired module's marker for the fix that made its own permission
     * predicate safe to call.
     *
     * Before it, asking for the grant panicked the kernel: the predicate
     * released a KDP-protected credential with a raw put_cred(), which is a
     * write to a hypervisor-read-only page (recorded by the firmware as
     * PC=allowed_for_su+0x12c, "synchronous external abort"). A caller cannot
     * detect that at run time, and the act of detecting it IS the crash - so
     * the module publishes this line and the caller reads it first.
     */
    public static final String EXPECTED_TRANSPORT_FIX = "kdp-cred-1";

    private static final Set<String> KEYS = Set.of(
            "state", "boot_id", "ksu_version", "uapi_version", "runtime_mode", "selinux");

    /*
     * Optional on purpose, and it must stay optional.
     *
     * A record written by the PREVIOUS pair has no transport_fix line, and that
     * pair still roots this device correctly. Requiring the key here would make
     * evaluate() refuse a perfectly good post-root state and break the chain on
     * every device that has not rebuilt yet. What the marker gates is one
     * thing - whether the supercall may be issued - and that question is asked
     * by supercallAllowed(), not by this verdict.
     */
    private static final Set<String> OPTIONAL_KEYS = Set.of("transport_fix");

    private PostRootStatus() {}

    /*
     * String.isBlank() is API 34; this app declares minSdk 32. On the pinned
     * ZZIC firmware (Android 17) the difference is invisible, but on a device
     * the manifest still claims to support, that call raises NoSuchMethodError
     * - an Error, not an Exception, so the caller's catch would not hold it and
     * the post-root wait would die with the dialog still spinning. A parser
     * whose whole job is to refuse must not be the thing that throws.
     */
    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    public static final class Verdict {
        public final boolean complete;
        public final String reason;
        /** The paired module's fix marker, or null when the record carries none. */
        public final String transportFix;

        private Verdict(boolean complete, String reason, String transportFix) {
            this.complete = complete;
            this.reason = reason;
            this.transportFix = transportFix;
        }
    }

    private static Verdict fail(String reason) {
        return new Verdict(false, reason, null);
    }

    /**
     * May the KernelSU driver-fd supercall be issued on this boot?
     *
     * Only when a complete, same-boot record says the loaded module carries the
     * fix. Every other answer - no record, another boot's record, no marker, a
     * marker this build does not know - is no. The cost of being wrong is a
     * kernel panic and a lost root session, so this is the one question where
     * absence of evidence has to read as absence of permission (AGENTS.md 2).
     */
    public static boolean supercallAllowed(Verdict verdict) {
        return verdict != null
                && verdict.complete
                && EXPECTED_TRANSPORT_FIX.equals(verdict.transportFix);
    }

    public static Verdict evaluate(String record, String currentBootId, int liveSelinux) {
        if (blank(record)) return fail("completion record absent or empty");
        if (blank(currentBootId)) return fail("current boot_id unavailable");

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
            if (!KEYS.contains(key) && !OPTIONAL_KEYS.contains(key)) {
                return fail("unknown status key: " + key);
            }
            if (values.putIfAbsent(key, value) != null) return fail("duplicate status key: " + key);
        }
        if (!values.keySet().containsAll(KEYS)) {
            return fail("completion record is missing required fields");
        }
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
        return new Verdict(true, "same-boot KernelSU + SELinux post-root contract complete",
                values.get("transport_fix"));
    }
}
