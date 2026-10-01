package com.polygraphene.df.reroot;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure policy for the Samsung boot-health handshake around a soft reboot.
 *
 * <h2>Why this exists at all</h2>
 *
 * On 2026-10-01 an Apply Modules tap on ZZIC reached ksud, the framework
 * restarted, the UI came back - and the device then took a FULL reboot on its
 * own. Three rounds of reasoning had previously blamed a kernel panic. The
 * persistent records refuted that: the DropBox entry for the event is
 * {@code SYSTEM_LAST_KMSG_0_20261001_140539_RP} (a reboot record, not the
 * {@code _KP} panic record this device also writes), and it names
 *
 * <pre>
 *   Last boot reason: reboot,rollback_staged_install(bootchecker_timeout)
 * </pre>
 *
 * while {@code dumpsys rollback} shows CrashRecovery two minutes earlier:
 *
 * <pre>
 *   Rolling back bootchecker_timeout. Reason: NATIVE_CRASH
 * </pre>
 *
 * The mechanism is in the firmware's own init script. {@code
 * /system/etc/init/bootchecker.rc} contains
 *
 * <pre>
 *   on property:init.svc.zygote=restarting
 *       setprop dev.platform_bootcomplete 0
 *       restart bootchecker
 * </pre>
 *
 * so ANY zygote restart - which is exactly what an emulated soft reboot is -
 * zeroes Samsung's own boot-completion flag and restarts Samsung's boot
 * watchdog. The flag is restored by a different trigger,
 * {@code on property:dev.bootcomplete=1}, and {@code dev.bootcomplete} is a
 * property KernelSU's {@code reset_boot_completed()} does not touch: it resets
 * {@code sys.boot_completed}. If {@code dev.bootcomplete} therefore stays at 1
 * across the restart, the edge trigger never re-fires, {@code
 * dev.platform_bootcomplete} stays 0, and the restarted {@code bootchecker}
 * times out waiting for a boot it believes never completed.
 *
 * <h2>What this class does, and what it very deliberately does NOT do</h2>
 *
 * It does not fix that. Nothing in this app can: the trigger lives in the
 * firmware's init rc and the property it keys on is written by a daemon running
 * outside our control. What it does is two separate things that the 2026-10-01
 * cycle had neither of:
 *
 * <ol>
 *   <li><b>A refusal.</b> {@link #verdict} classifies the boot-health state
 *       BEFORE the teardown. Asking for a second userspace teardown while the
 *       first handshake has not converged - {@code dev.platform_bootcomplete}
 *       already 0, {@code bootchecker} already restarted, CrashRecovery already
 *       attempting a reboot - is strictly worse than refusing, and only a
 *       positive {@link #CONVERGED} permits the dispatch.</li>
 *   <li><b>A measurement.</b> The dispatching process is killed by {@code stop},
 *       so it can never report what happened next. The record this class formats
 *       is written before the exec and completed by the restarted framework's own
 *       BOOT_COMPLETED in the SAME boot, which is the only observer that exists.
 *       Its {@code post_*} half is what finally answers whether {@code
 *       dev.bootcomplete} re-transitions and {@code dev.platform_bootcomplete}
 *       comes back - the central open hypothesis above.</li>
 * </ol>
 *
 * <h2>Why "unset" and "unreadable" are different values</h2>
 *
 * {@code sys.init.updatable_crashing} and {@code crashrecovery.attempting_reboot}
 * are absent on a healthy boot: init sets them only in the bad case. So an empty
 * read is a POSITIVE fact here ({@link #ABSENT}), while a failure of the read
 * mechanism itself is {@link #UNKNOWN} and refuses. Collapsing the two would
 * either make the gate unsatisfiable (every healthy boot reads UNKNOWN) or make
 * an unreadable crash signal look like a clean one. AGENTS.md 3.7.
 */
public final class SoftRebootHealthPolicy {

    /** The property is set and this is its value - these are read, never guessed. */
    public static final String PROP_SYS_BOOT_COMPLETED = "sys.boot_completed";
    public static final String PROP_DEV_BOOTCOMPLETE = "dev.bootcomplete";
    public static final String PROP_DEV_PLATFORM_BOOTCOMPLETE = "dev.platform_bootcomplete";
    public static final String PROP_INIT_SVC_ZYGOTE = "init.svc.zygote";
    public static final String PROP_INIT_SVC_BOOTCHECKER = "init.svc.bootchecker";
    public static final String PROP_INIT_SVC_BOOTCHECKER_BOOTC = "init.svc.bootchecker-bootc";
    public static final String PROP_CRASHRECOVERY_ATTEMPTING_REBOOT =
            "crashrecovery.attempting_reboot";
    public static final String PROP_UPDATABLE_CRASHING = "sys.init.updatable_crashing";

    /**
     * Every property in one snapshot, in a fixed order so the record is stable.
     *
     * All eight are load-bearing and none is a duplicate of another:
     * {@code sys.boot_completed} is AOSP's flag and the one KernelSU resets;
     * {@code dev.bootcomplete} is Samsung's, and is the subject of the trigger
     * that restores the third; {@code dev.platform_bootcomplete} is the flag
     * bootchecker.rc zeroes on a zygote restart; {@code init.svc.zygote} is the
     * property that fires that trigger; the two bootchecker service states say
     * whether Samsung's watchdog is in flight or has finished; and the last two
     * are CrashRecovery's own, which is what turned a timeout into a rollback.
     */
    public static final List<String> PROPERTIES = Collections.unmodifiableList(Arrays.asList(
            PROP_SYS_BOOT_COMPLETED,
            PROP_DEV_BOOTCOMPLETE,
            PROP_DEV_PLATFORM_BOOTCOMPLETE,
            PROP_INIT_SVC_ZYGOTE,
            PROP_INIT_SVC_BOOTCHECKER,
            PROP_INIT_SVC_BOOTCHECKER_BOOTC,
            PROP_CRASHRECOVERY_ATTEMPTING_REBOOT,
            PROP_UPDATABLE_CRASHING));

    /** The property exists and init has not set it. A fact, not a failure. */
    public static final String ABSENT = "ABSENT";

    /** The read mechanism failed. Never a value, and never permission. */
    public static final String UNKNOWN = "UNKNOWN";

    /** Samsung's handshake is complete: this is the only state that permits a dispatch. */
    public static final String CONVERGED = "BOOT_HEALTH_CONVERGED";

    /** Readable, accounted for, and not converged (yet, or any more). */
    public static final String PENDING = "BOOT_HEALTH_PENDING";

    /** CrashRecovery is already acting. The 2026-10-01 state, two minutes in. */
    public static final String CRASH_RECOVERY = "BOOT_HEALTH_CRASH_RECOVERY";

    /** Something could not be read, or read as a value this build cannot account for. */
    public static final String HEALTH_UNKNOWN = "BOOT_HEALTH_UNKNOWN";

    public static final String PHASE_PRE_EXEC = "PRE_EXEC";
    public static final String PHASE_POST_EXEC = "POST_EXEC";

    /** No record at all: no Apply Modules dispatch reached the exec in any boot. */
    public static final String OBS_ABSENT = "SOFT_REBOOT_HEALTH_ABSENT";
    public static final String OBS_UNREADABLE = "SOFT_REBOOT_HEALTH_UNREADABLE";
    public static final String OBS_MALFORMED = "SOFT_REBOOT_HEALTH_MALFORMED";
    /** A record from an earlier boot. It survives a full reboot and claims nothing here. */
    public static final String OBS_STALE_BOOT = "SOFT_REBOOT_HEALTH_STALE_BOOT";
    /**
     * The pre-exec half only. Either the framework never came back, or it came
     * back without this receiver running. Those two are not separated here, and
     * saying so is the point: one absent half is one absent half.
     */
    public static final String OBS_PRE_EXEC_ONLY = "SOFT_REBOOT_HEALTH_PRE_EXEC_ONLY";
    /** Both halves, same boot. The post verdict is the measurement. */
    public static final String OBS_POST_EXEC = "SOFT_REBOOT_HEALTH_POST_EXEC";

    private static final String PRE = "pre_";
    private static final String POST = "post_";
    private static final String KEY_PHASE = "phase";
    private static final String KEY_BOOT_ID = "boot_id";
    private static final String KEY_VERDICT = "verdict";
    private static final String KEY_ELAPSED_MS = "elapsed_ms";
    private static final String KEY_PID = "pid";

    private static final Set<String> PHASES = Set.of(PHASE_PRE_EXEC, PHASE_POST_EXEC);
    private static final Set<String> VERDICTS =
            Set.of(CONVERGED, PENDING, CRASH_RECOVERY, HEALTH_UNKNOWN);

    /** init's own service states. Anything else is a value this build cannot read. */
    private static final Set<String> INIT_SVC_STATES =
            Set.of("running", "stopped", "stopping", "restarting", ABSENT);

    private SoftRebootHealthPolicy() {}

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** The record key a property contributes under, e.g. {@code pre_dev_bootcomplete}. */
    static String keyFor(String prefix, String property) {
        return prefix + property.replace('.', '_').replace('-', '_');
    }

    /**
     * One reading of the eight properties plus who read them and when.
     *
     * {@code pid} is not decoration: this app runs in the {@code system} process,
     * so a different pid in the post half is direct evidence that
     * {@code system_server} itself was replaced rather than merely re-entered.
     */
    public static final class Snapshot {
        private final Map<String, String> properties = new LinkedHashMap<>();
        public long elapsedMs = -1L;
        public int pid = -1;

        /** An empty or null reading is {@link #ABSENT}; a failed read must pass UNKNOWN. */
        public Snapshot put(String property, String value) {
            properties.put(property, blank(value) ? ABSENT : value.trim());
            return this;
        }

        public String get(String property) {
            String v = properties.get(property);
            return v == null ? UNKNOWN : v;
        }
    }

    /** A snapshot in which nothing could be read. Every property refuses. */
    public static Snapshot unreadableSnapshot(long elapsedMs, int pid) {
        Snapshot s = new Snapshot();
        for (String p : PROPERTIES) s.properties.put(p, UNKNOWN);
        s.elapsedMs = elapsedMs;
        s.pid = pid;
        return s;
    }

    /**
     * Classify a snapshot. Fail-closed: anything unreadable or unrecognised is
     * {@link #HEALTH_UNKNOWN}, and only an all-positive reading is
     * {@link #CONVERGED}.
     *
     * The order matters. An unreadable property is checked first, because a
     * crash signal that could not be read must not be able to produce PENDING
     * (which reads like "just wait"), and a CrashRecovery signal is checked
     * before convergence, because the flags can momentarily all be 1 while
     * CrashRecovery is already rolling back.
     */
    public static String verdict(Snapshot s) {
        if (s == null) return HEALTH_UNKNOWN;
        for (String p : PROPERTIES) {
            if (UNKNOWN.equals(s.get(p))) return HEALTH_UNKNOWN;
        }
        String attemptingReboot = s.get(PROP_CRASHRECOVERY_ATTEMPTING_REBOOT);
        if ("true".equals(attemptingReboot)) return CRASH_RECOVERY;
        if (!ABSENT.equals(attemptingReboot) && !"false".equals(attemptingReboot)) {
            // A tri-state property with a fourth value is not a state this build knows.
            return HEALTH_UNKNOWN;
        }
        String crashing = s.get(PROP_UPDATABLE_CRASHING);
        if (!ABSENT.equals(crashing) && !"0".equals(crashing) && !"false".equals(crashing)) {
            return CRASH_RECOVERY;
        }
        for (String p : List.of(PROP_INIT_SVC_ZYGOTE, PROP_INIT_SVC_BOOTCHECKER,
                PROP_INIT_SVC_BOOTCHECKER_BOOTC)) {
            if (!INIT_SVC_STATES.contains(s.get(p))) return HEALTH_UNKNOWN;
        }
        /*
         * The three boot-completion flags, and then the two services that own the
         * Samsung half of the handshake. On a healthy ZZIC full boot the observed
         * state is exactly 1/1/1 with both bootchecker services `stopped` - they
         * are `oneshot`, so `stopped` is their finished state, and `running` means
         * the watchdog is still waiting for a boot to complete.
         */
        if (!"1".equals(s.get(PROP_SYS_BOOT_COMPLETED))) return PENDING;
        if (!"1".equals(s.get(PROP_DEV_BOOTCOMPLETE))) return PENDING;
        if (!"1".equals(s.get(PROP_DEV_PLATFORM_BOOTCOMPLETE))) return PENDING;
        if (!"running".equals(s.get(PROP_INIT_SVC_ZYGOTE))) return PENDING;
        if (!"stopped".equals(s.get(PROP_INIT_SVC_BOOTCHECKER))) return PENDING;
        if (!"stopped".equals(s.get(PROP_INIT_SVC_BOOTCHECKER_BOOTC))) return PENDING;
        return CONVERGED;
    }

    /** The pre-exec half of the record, written before the teardown. */
    public static String formatPreExec(String bootId, Snapshot pre) {
        StringBuilder sb = new StringBuilder();
        sb.append(KEY_PHASE).append('=').append(PHASE_PRE_EXEC).append('\n');
        sb.append(KEY_BOOT_ID).append('=').append(bootId).append('\n');
        appendHalf(sb, PRE, pre);
        return sb.toString();
    }

    /**
     * Complete the record with the post-restart half, or refuse.
     *
     * Returns null unless {@code existing} is a well-formed PRE_EXEC record for
     * {@code currentBootId}. A post half written over another boot's record, or
     * over a record that is already complete, would be a second observation
     * presented as the first (AGENTS.md 3.8), so there is no such path.
     */
    public static String formatPostExec(String existing, String currentBootId, Snapshot post) {
        if (blank(currentBootId)) return null;
        Map<String, String> parsed = parse(existing);
        if (parsed == null) return null;
        if (!PHASE_PRE_EXEC.equals(parsed.get(KEY_PHASE))) return null;
        if (!currentBootId.equals(parsed.get(KEY_BOOT_ID))) return null;
        StringBuilder sb = new StringBuilder();
        sb.append(KEY_PHASE).append('=').append(PHASE_POST_EXEC).append('\n');
        sb.append(KEY_BOOT_ID).append('=').append(parsed.get(KEY_BOOT_ID)).append('\n');
        for (String key : halfKeys(PRE)) {
            sb.append(key).append('=').append(parsed.get(key)).append('\n');
        }
        appendHalf(sb, POST, post);
        return sb.toString();
    }

    private static void appendHalf(StringBuilder sb, String prefix, Snapshot s) {
        sb.append(prefix).append(KEY_VERDICT).append('=').append(verdict(s)).append('\n');
        sb.append(prefix).append(KEY_ELAPSED_MS).append('=')
                .append(s == null ? -1L : s.elapsedMs).append('\n');
        sb.append(prefix).append(KEY_PID).append('=')
                .append(s == null ? -1 : s.pid).append('\n');
        for (String p : PROPERTIES) {
            sb.append(keyFor(prefix, p)).append('=')
                    .append(s == null ? UNKNOWN : s.get(p)).append('\n');
        }
    }

    private static Set<String> halfKeys(String prefix) {
        Set<String> keys = new LinkedHashSet<>();
        keys.add(prefix + KEY_VERDICT);
        keys.add(prefix + KEY_ELAPSED_MS);
        keys.add(prefix + KEY_PID);
        for (String p : PROPERTIES) keys.add(keyFor(prefix, p));
        return keys;
    }

    /** What a stored record says, with every "not this" kept apart from every other. */
    public static final class Observation {
        public final String state;
        /** The verdict recorded before the teardown, or null when there is none. */
        public final String preVerdict;
        /** The verdict recorded by the restarted framework, or null. */
        public final String postVerdict;
        /** 1 = system process replaced, 0 = same pid, -1 = not decidable. */
        public final int systemProcessReplaced;

        private Observation(String state, String preVerdict, String postVerdict,
                int systemProcessReplaced) {
            this.state = state;
            this.preVerdict = preVerdict;
            this.postVerdict = postVerdict;
            this.systemProcessReplaced = systemProcessReplaced;
        }
    }

    private static Observation plain(String state) {
        return new Observation(state, null, null, -1);
    }

    /**
     * Read a stored record against the CURRENT boot.
     *
     * Soft-reboot artefacts survive a full reboot - the trace and lock from boot
     * {@code 85e3a031…} were still on disk in boot {@code 68845faf…} - so a record
     * is evidence about this boot only when it names this boot. Anything else is
     * {@link #OBS_STALE_BOOT}, which is a different fact from "no dispatch ever
     * happened" and must never be displayed as one.
     */
    public static Observation observe(String record, String currentBootId) {
        if (record == null) return plain(OBS_ABSENT);
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return plain(OBS_UNREADABLE);
        Map<String, String> parsed = parse(record);
        if (parsed == null) return plain(OBS_MALFORMED);
        if (blank(currentBootId) || !currentBootId.equals(parsed.get(KEY_BOOT_ID))) {
            return new Observation(OBS_STALE_BOOT, parsed.get(PRE + KEY_VERDICT),
                    parsed.get(POST + KEY_VERDICT), -1);
        }
        if (PHASE_PRE_EXEC.equals(parsed.get(KEY_PHASE))) {
            return new Observation(OBS_PRE_EXEC_ONLY, parsed.get(PRE + KEY_VERDICT), null, -1);
        }
        int prePid = number(parsed.get(PRE + KEY_PID));
        int postPid = number(parsed.get(POST + KEY_PID));
        int replaced = (prePid < 0 || postPid < 0) ? -1 : (prePid == postPid ? 0 : 1);
        return new Observation(OBS_POST_EXEC, parsed.get(PRE + KEY_VERDICT),
                parsed.get(POST + KEY_VERDICT), replaced);
    }

    private static int number(String raw) {
        if (blank(raw)) return -1;
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * null on anything this build cannot fully account for: an unknown key, a
     * duplicate, a missing half, a phase or verdict outside the enumerations.
     *
     * Strict in both directions on purpose. A PRE_EXEC record carrying post_*
     * keys, or a POST_EXEC record missing them, is not a record whose halves can
     * be told apart, and telling them apart is this file's only job.
     */
    static Map<String, String> parse(String record) {
        if (blank(record)) return null;
        Map<String, String> values = new HashMap<>();
        for (String raw : record.split("\\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int separator = line.indexOf('=');
            if (separator <= 0 || separator == line.length() - 1) return null;
            String key = line.substring(0, separator);
            if (values.putIfAbsent(key, line.substring(separator + 1)) != null) return null;
        }
        String phase = values.get(KEY_PHASE);
        if (phase == null || !PHASES.contains(phase)) return null;
        if (blank(values.get(KEY_BOOT_ID))) return null;
        Set<String> expected = new LinkedHashSet<>();
        expected.add(KEY_PHASE);
        expected.add(KEY_BOOT_ID);
        expected.addAll(halfKeys(PRE));
        if (PHASE_POST_EXEC.equals(phase)) expected.addAll(halfKeys(POST));
        if (!values.keySet().equals(expected)) return null;
        if (!VERDICTS.contains(values.get(PRE + KEY_VERDICT))) return null;
        if (PHASE_POST_EXEC.equals(phase)
                && !VERDICTS.contains(values.get(POST + KEY_VERDICT))) {
            return null;
        }
        return values;
    }
}
