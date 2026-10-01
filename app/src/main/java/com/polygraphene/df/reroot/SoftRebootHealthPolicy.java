package com.polygraphene.df.reroot;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure policy for the OEM boot-health handshake around a soft reboot.
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
 * <h2>What is observed, and what is not</h2>
 *
 * Observed, in the firmware's own {@code /system/etc/init/bootchecker.rc}:
 *
 * <pre>
 *   on property:init.svc.zygote=restarting
 *       setprop dev.platform_bootcomplete 0
 *       restart bootchecker
 *
 *   on property:dev.bootcomplete=1
 *       setprop dev.platform_bootcomplete 1
 *       start bootchecker-bootc
 * </pre>
 *
 * So any zygote restart - which is what an emulated soft reboot produces -
 * zeroes the OEM boot-completion flag and restarts the OEM boot watchdog, and
 * the rule that restores that flag is keyed on {@code dev.bootcomplete=1}.
 *
 * <b>NOT observed, and deliberately not asserted anywhere in this file:</b> what
 * happens to {@code dev.bootcomplete} after the restart. An earlier version of
 * this comment, and of the docs, claimed the rule was "edge triggered" and
 * therefore could not re-fire while the property "stayed 1". That is a claim
 * about init's property-change dispatch that nobody here verified - init queues
 * a matching action when a property is <i>set</i>, and whether a value-preserving
 * set re-queues it was never read out of the source. AGENTS.md 3.6.1 exists
 * because this investigation has already named three causes it could not
 * evidence. So the open question is stated as a question:
 *
 * <pre>
 *   does anything on this firmware set dev.bootcomplete=1 again after an
 *   emulated soft reboot, and does dev.platform_bootcomplete come back?
 * </pre>
 *
 * Nobody has read those two properties after a soft reboot on this firmware.
 * That reading is what the record below exists to take.
 *
 * <h2>What this class does, and what it very deliberately does NOT do</h2>
 *
 * It does not fix anything. The trigger lives in the firmware's init rc and the
 * property it keys on is written by a daemon outside this app. What it does is
 * two separate things that the 2026-10-01 cycle had neither of:
 *
 * <ol>
 *   <li><b>A refusal.</b> {@link #verdict} classifies the boot-health state
 *       BEFORE the teardown, and only a positive {@link #CONVERGED} (or a
 *       device with no such handshake at all) permits the dispatch. Note what
 *       this does and does not add: the per-boot soft-reboot lock ALREADY makes
 *       a second DFR Apply Modules in one boot impossible. What this gate adds
 *       is refusing the FIRST attempt in a boot whose health is already bad for
 *       some other reason - an unrelated framework restart, a rollback already
 *       in flight.</li>
 *   <li><b>A measurement.</b> The dispatching process is killed by {@code stop},
 *       so it cannot report what happened next. The record is written before the
 *       exec and completed by the restarted framework in the SAME boot.</li>
 * </ol>
 *
 * <h2>Why one post-restart sample proves nothing</h2>
 *
 * This is the property the whole design turns on, and it was got wrong once.
 * The incident's own timeline is long: the framework returned, CrashRecovery
 * rolled back about two minutes later, the device rebooted about two minutes
 * after that. So:
 *
 * <ul>
 *   <li>a first sample reading PENDING proves nothing - {@code
 *       dev.platform_bootcomplete} is restored by an init trigger and {@code
 *       bootchecker-bootc} is a oneshot that is briefly {@code running}, so a
 *       healthy boot can read PENDING for a moment;</li>
 *   <li>and a first sample reading CONVERGED proves nothing either - the device
 *       that rebooted had a working UI for minutes first. Stopping the
 *       observation at the first CONVERGED would turn "it converged at T+100ms"
 *       into "the hypothesis is refuted", on a device that then reproduced the
 *       failure at T+2min.</li>
 * </ul>
 *
 * The observation window therefore runs to a <b>deadline</b>, never to a
 * verdict. {@code post_settled} means the window closed, not that an answer
 * arrived; {@code post_first_verdict} keeps the first reading;
 * {@code post_converged_seen} and {@code post_crash_recovery_seen} are sticky,
 * so a CONVERGED that is later followed by CrashRecovery is visible as both.
 *
 * <h2>Why "unset" and "unreadable" are different values</h2>
 *
 * {@code sys.init.updatable_crashing} and {@code crashrecovery.attempting_reboot}
 * are absent on a healthy boot: init sets them only in the bad case. So an empty
 * read is a POSITIVE fact here ({@link #ABSENT}), while a failure of the read
 * mechanism itself is {@link #UNKNOWN} and refuses. Collapsing the two would
 * either make the gate unsatisfiable (every healthy boot reads UNKNOWN) or make
 * an unreadable crash signal look like a clean one. AGENTS.md 3.7.
 *
 * <h2>Why a device without the handshake is NOT_APPLICABLE, not PENDING</h2>
 *
 * This is an OEM mechanism. {@code bootchecker} is a Samsung binary and
 * {@code dev.platform_bootcomplete} a Samsung property, so on an unrelated
 * device none of them exists - and an earlier version of this policy therefore
 * returned PENDING there and refused Apply Modules on every device but this one.
 * That is wrong by AGENTS.md section 1: an unrelated device takes the unchanged
 * upstream path, and this action is reachable off-target (a generic device
 * running the bundled daemon can satisfy {@link PostRootStatus}). So a boot that
 * AOSP itself calls complete while the whole OEM mechanism left no trace gets
 * {@link #NOT_APPLICABLE} - "not a candidate", which AGENTS.md section 5 already
 * treats as a success rather than a defect.
 *
 * That verdict is deliberately unreachable on the target: it requires ALL of the
 * OEM-only properties to be positively unset, and a failure of the read
 * mechanism yields UNKNOWN rather than ABSENT. A PARTIALLY present mechanism is
 * PENDING, which refuses - the fail-closed direction.
 */
public final class SoftRebootHealthPolicy {

    /**
     * The record format's own version.
     *
     * The file survives a full reboot and the app that wrote it can be replaced,
     * so "this is not a record this build wrote" has to be separable from "this
     * record is corrupt". Without it, an older schema and a damaged file are the
     * same observation.
     */
    public static final int SCHEMA_VERSION = 2;

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
     * Every property the VERDICT is computed from, in a fixed order.
     *
     * All eight are load-bearing and none is a duplicate of another:
     * {@code sys.boot_completed} is AOSP's flag and the one KernelSU resets;
     * {@code dev.bootcomplete} is the subject of the trigger that restores the
     * third; {@code dev.platform_bootcomplete} is the flag bootchecker.rc zeroes
     * on a zygote restart; {@code init.svc.zygote} is the property that fires
     * that trigger; the two bootchecker service states say whether the OEM
     * watchdog is in flight or has finished; and the last two are CrashRecovery's
     * own, which is what turned a timeout into a rollback.
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

    public static final String PROP_UPDATABLE_CRASHING_PROCESS_NAME =
            "sys.init.updatable_crashing_process_name";
    public static final String PROP_DEV_ATTEMPTING_REBOOT = "dev.attempting_reboot";

    /**
     * Recorded, never gated on.
     *
     * {@code /system/bin/bootchecker} carries both strings, and the incident's
     * CrashRecovery entry named {@code bootchecker_timeout} - so the process name
     * beside the boolean is far more discriminating than the boolean alone. They
     * stay OUT of {@link #PROPERTIES} on purpose: an unreadable telemetry field
     * must not be able to refuse a dispatch, because nothing decides anything
     * from it. AGENTS.md 3.7 wants the facts separate, not all of them promoted
     * to gates.
     */
    public static final List<String> TELEMETRY = Collections.unmodifiableList(Arrays.asList(
            PROP_UPDATABLE_CRASHING_PROCESS_NAME,
            PROP_DEV_ATTEMPTING_REBOOT));

    private static final List<String> ALL_PROPERTIES;
    static {
        List<String> all = new ArrayList<>(PROPERTIES);
        all.addAll(TELEMETRY);
        ALL_PROPERTIES = Collections.unmodifiableList(all);
    }

    /**
     * The properties that exist only because this firmware runs the OEM boot
     * watchdog. All of them positively unset is what makes a device "not a
     * candidate"; any ONE of them present means the mechanism is there.
     */
    private static final List<String> OEM_ONLY = List.of(
            PROP_DEV_PLATFORM_BOOTCOMPLETE,
            PROP_INIT_SVC_BOOTCHECKER,
            PROP_INIT_SVC_BOOTCHECKER_BOOTC);

    /** The property exists and init has not set it. A fact, not a failure. */
    public static final String ABSENT = "ABSENT";

    /** The read mechanism failed. Never a value, and never permission. */
    public static final String UNKNOWN = "UNKNOWN";

    /** The handshake is complete: one of the two states that permit a dispatch. */
    public static final String CONVERGED = "BOOT_HEALTH_CONVERGED";

    /** Readable, accounted for, and not converged (yet, or any more). */
    public static final String PENDING = "BOOT_HEALTH_PENDING";

    /** CrashRecovery is already acting. The 2026-10-01 state, two minutes in. */
    public static final String CRASH_RECOVERY = "BOOT_HEALTH_CRASH_RECOVERY";

    /** Something could not be read, or read as a value this build cannot account for. */
    public static final String HEALTH_UNKNOWN = "BOOT_HEALTH_UNKNOWN";

    /** This device runs no OEM boot watchdog, so this policy has nothing to say. */
    public static final String NOT_APPLICABLE = "BOOT_HEALTH_NOT_APPLICABLE";

    public static final String PHASE_PRE_EXEC = "PRE_EXEC";
    public static final String PHASE_POST_EXEC = "POST_EXEC";

    /*
     * What this process managed to record about the exec itself.
     *
     * The pre half is written BEFORE the exec, so its presence proves the exec
     * was reached - never that a soft reboot was dispatched. The refusal paths
     * (a digest that changed under us, a lost transport, a shell past its
     * deadline) all return with this process alive and must be able to say so,
     * or a record that executed nothing would be read as a framework that never
     * came back.
     */
    /** The pre half's value: nothing after the exec has run yet. */
    public static final String EXEC_NOT_REACHED = "NOT_REACHED";
    /** A refusal landed between the pre half and the exec; nothing was executed. */
    public static final String EXEC_NOT_ATTEMPTED = "NOT_ATTEMPTED";
    /** The bytes at the chosen path were no longer the pinned daemon. */
    public static final String EXEC_REFUSED_DIGEST = "REFUSED_DIGEST";
    /** The root transport could not be started again. */
    public static final String EXEC_TRANSPORT_LOST = "TRANSPORT_LOST";
    /** The shell outlived its deadline; whether ksud got the command is unknown. */
    public static final String EXEC_UNDETERMINED = "UNDETERMINED";
    /** ksud exited non-zero. */
    public static final String EXEC_FAILED = "FAILED";
    /**
     * ksud returned, and this process survived it.
     *
     * Ambiguous by construction and kept that way: {@code soft_reboot()} exits 0
     * both when it daemonises and when it skips the operation on a UAPI mismatch.
     */
    public static final String EXEC_RETURNED = "RETURNED";

    /** No record at all: no Apply Modules dispatch has reached the exec in any boot. */
    public static final String OBS_ABSENT = "SOFT_REBOOT_HEALTH_ABSENT";
    public static final String OBS_UNREADABLE = "SOFT_REBOOT_HEALTH_UNREADABLE";
    public static final String OBS_MALFORMED = "SOFT_REBOOT_HEALTH_MALFORMED";
    /** A well-formed record from a schema this build does not write. */
    public static final String OBS_OTHER_SCHEMA = "SOFT_REBOOT_HEALTH_OTHER_SCHEMA";
    /** A record from an earlier boot. It survives a full reboot and claims nothing here. */
    public static final String OBS_STALE_BOOT = "SOFT_REBOOT_HEALTH_STALE_BOOT";
    /**
     * The pre-exec half only. What that means depends entirely on
     * {@link Observation#execOutcome}, which is why the two are separate fields:
     * a torn-down framework and an exec that refused leave the same phase.
     */
    public static final String OBS_PRE_EXEC_ONLY = "SOFT_REBOOT_HEALTH_PRE_EXEC_ONLY";
    /** Both halves, same boot. The window state, not the verdict, says if it is done. */
    public static final String OBS_POST_EXEC = "SOFT_REBOOT_HEALTH_POST_EXEC";

    /** Process identity across the restart, as far as the evidence decides it. */
    public static final String PROC_REPLACED = "REPLACED";
    public static final String PROC_SAME = "SAME";
    public static final String PROC_UNDECIDED = "UNDECIDED";

    private static final String PRE = "pre_";
    private static final String POST = "post_";
    private static final String KEY_SCHEMA = "schema_version";
    private static final String KEY_PHASE = "phase";
    private static final String KEY_BOOT_ID = "boot_id";
    private static final String KEY_EXEC_OUTCOME = "exec_outcome";
    private static final String KEY_VERDICT = "verdict";
    /** When the property sweep STARTED. See {@link Snapshot} on why both ends. */
    private static final String KEY_READ_START_MS = "read_start_ms";
    /** When it finished. The span is how far from atomic this "snapshot" was. */
    private static final String KEY_READ_END_MS = "read_end_ms";
    private static final String KEY_PID = "pid";
    /** {@code /proc/self/stat} field 22: distinguishes a reused pid from a kept one. */
    private static final String KEY_PROC_STARTTIME = "proc_starttime";
    /** The FIRST post verdict, kept alongside the latest so a change is visible. */
    private static final String KEY_POST_FIRST_VERDICT = "post_first_verdict";
    /** How many post observations were recorded, never how many were sampled. */
    private static final String KEY_POST_OBSERVATIONS = "post_observations";
    /** 1 once the observation WINDOW closed. Not "an answer arrived". */
    private static final String KEY_POST_SETTLED = "post_settled";
    /** Sticky: CONVERGED was seen at least once during the window. */
    private static final String KEY_POST_CONVERGED_SEEN = "post_converged_seen";
    /** Sticky: CrashRecovery was seen at least once during the window. */
    private static final String KEY_POST_CRASH_SEEN = "post_crash_recovery_seen";

    private static final Set<String> PHASES = Set.of(PHASE_PRE_EXEC, PHASE_POST_EXEC);
    private static final Set<String> VERDICTS = Set.of(
            CONVERGED, PENDING, CRASH_RECOVERY, HEALTH_UNKNOWN, NOT_APPLICABLE);
    private static final Set<String> EXEC_OUTCOMES = Set.of(
            EXEC_NOT_REACHED, EXEC_NOT_ATTEMPTED, EXEC_REFUSED_DIGEST, EXEC_TRANSPORT_LOST,
            EXEC_UNDETERMINED, EXEC_FAILED, EXEC_RETURNED);

    /** init's own service states. Anything else is a value this build cannot read. */
    private static final Set<String> INIT_SVC_STATES =
            Set.of("running", "stopped", "stopping", "restarting", ABSENT);

    /**
     * Gating properties followed by telemetry, as one list for a caller that has
     * to read all of them.
     *
     * An accessor rather than asking the caller to concatenate two lists: the
     * Kotlin side would be joining two platform-typed {@code List<String!>}, and
     * the record's key set is derived from this exact order, so one definition of
     * it is better than two.
     */
    public static List<String> allProperties() {
        return ALL_PROPERTIES;
    }

    private SoftRebootHealthPolicy() {}

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** The record key a property contributes under, e.g. {@code pre_dev_bootcomplete}. */
    static String keyFor(String prefix, String property) {
        return prefix + property.replace('.', '_').replace('-', '_');
    }

    /**
     * One sweep of the properties, plus who read them and when - at both ends.
     *
     * <b>It is not atomic, and the field names no longer pretend otherwise.</b>
     * The reading is N separate property lookups in a row, taken during the one
     * phase of boot characterised by things changing quickly, so the result can
     * be a combination that never existed simultaneously. {@code read_start_ms}
     * and {@code read_end_ms} bound the interval it was assembled over, which is
     * the honest form of the claim: a reader can see how wide the sweep was and
     * discount a verdict assembled across a long one.
     *
     * {@code pid} and {@code proc_starttime} are both recorded because pid alone
     * cannot answer the question people want from it: pids are reused, so two
     * halves sharing one is NOT evidence that the process was the same.
     */
    public static final class Snapshot {
        private final Map<String, String> properties = new LinkedHashMap<>();
        /** -1 for a reading that failed; never a second spelling of a value. */
        public long readStartMs = -1L;
        public long readEndMs = -1L;
        public long pid = -1L;
        public long procStarttime = -1L;

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
    public static Snapshot unreadableSnapshot(long readStartMs, long pid) {
        Snapshot s = new Snapshot();
        for (String p : ALL_PROPERTIES) s.properties.put(p, UNKNOWN);
        s.readStartMs = readStartMs;
        s.readEndMs = readStartMs;
        s.pid = pid;
        return s;
    }

    /**
     * Classify a snapshot. Fail-closed: anything unreadable or unrecognised is
     * {@link #HEALTH_UNKNOWN}, and only an all-positive reading is
     * {@link #CONVERGED}.
     *
     * The order matters, and three steps of it are load-bearing rather than
     * cosmetic. An unreadable property is checked first, because a crash signal
     * that could not be read must not be able to produce PENDING (which reads
     * like "just wait"). CrashRecovery is checked before convergence, because
     * the flags can momentarily all be 1 while CrashRecovery is already rolling
     * back - and before applicability, because CrashRecovery is AOSP's and a
     * rollback in flight is a bad moment for a userspace teardown on any device.
     * Applicability is checked before the per-flag comparisons, because those
     * compare against values an unrelated device never sets.
     *
     * Only {@link #PROPERTIES} is consulted. {@link #TELEMETRY} is recorded
     * beside the verdict and never decides it.
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
        /*
         * Not a candidate: AOSP itself calls the boot complete and the entire OEM
         * mechanism left no trace. Requires ALL of the OEM-only properties to be
         * positively unset, so a partially present mechanism stays PENDING (which
         * refuses) and an unreadable one is already UNKNOWN above. Unreachable on
         * the pinned target, where all three exist.
         */
        if ("1".equals(s.get(PROP_SYS_BOOT_COMPLETED))) {
            boolean oemPresent = false;
            for (String p : OEM_ONLY) {
                if (!ABSENT.equals(s.get(p))) oemPresent = true;
            }
            if (!oemPresent) return NOT_APPLICABLE;
        }
        for (String p : List.of(PROP_INIT_SVC_ZYGOTE, PROP_INIT_SVC_BOOTCHECKER,
                PROP_INIT_SVC_BOOTCHECKER_BOOTC)) {
            if (!INIT_SVC_STATES.contains(s.get(p))) return HEALTH_UNKNOWN;
        }
        /*
         * The three boot-completion flags, and then the two services that own the
         * OEM half of the handshake. On a healthy ZZIC full boot the observed
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
        sb.append(KEY_SCHEMA).append('=').append(SCHEMA_VERSION).append('\n');
        sb.append(KEY_PHASE).append('=').append(PHASE_PRE_EXEC).append('\n');
        sb.append(KEY_BOOT_ID).append('=').append(bootId).append('\n');
        sb.append(KEY_EXEC_OUTCOME).append('=').append(EXEC_NOT_REACHED).append('\n');
        appendHalf(sb, PRE, pre);
        return sb.toString();
    }

    /**
     * Record what this process saw of the exec, or refuse.
     *
     * Returns null unless {@code existing} is a PRE_EXEC record for this boot
     * whose outcome is still {@link #EXEC_NOT_REACHED}. Written once: a second
     * write would be a second claim about one call, and the first one came from
     * the code path that actually took it.
     */
    public static String formatExecOutcome(String existing, String currentBootId,
            String outcome) {
        if (blank(currentBootId) || blank(outcome)) return null;
        if (!EXEC_OUTCOMES.contains(outcome) || EXEC_NOT_REACHED.equals(outcome)) return null;
        Map<String, String> parsed = parse(existing);
        if (parsed == null) return null;
        if (!PHASE_PRE_EXEC.equals(parsed.get(KEY_PHASE))) return null;
        if (!currentBootId.equals(parsed.get(KEY_BOOT_ID))) return null;
        if (!EXEC_NOT_REACHED.equals(parsed.get(KEY_EXEC_OUTCOME))) return null;
        StringBuilder sb = new StringBuilder();
        sb.append(KEY_SCHEMA).append('=').append(SCHEMA_VERSION).append('\n');
        sb.append(KEY_PHASE).append('=').append(PHASE_PRE_EXEC).append('\n');
        sb.append(KEY_BOOT_ID).append('=').append(parsed.get(KEY_BOOT_ID)).append('\n');
        sb.append(KEY_EXEC_OUTCOME).append('=').append(outcome).append('\n');
        for (String key : halfKeys(PRE)) {
            sb.append(key).append('=').append(parsed.get(key)).append('\n');
        }
        return sb.toString();
    }

    /**
     * Add or replace the post-restart half, or refuse.
     *
     * Accepts a well-formed record for {@code currentBootId} whose observation
     * window has NOT closed - either the PRE_EXEC half (the first observation) or
     * a POST_EXEC half with {@code post_settled=0} (a re-sample).
     *
     * <b>A verdict never closes the window; only {@code windowClosed} does.</b>
     * That is the correction this method exists in its current form for: an
     * earlier version stopped at the first CONVERGED or CRASH_RECOVERY, which
     * would have reported "the handshake re-converges, hypothesis refuted" from a
     * sample taken 100ms in - on a device whose observed failure arrived two
     * minutes later. The sticky {@code post_converged_seen} /
     * {@code post_crash_recovery_seen} flags are how a CONVERGED that is later
     * followed by a rollback stays visible as both facts.
     */
    public static String formatPostExec(String existing, String currentBootId, Snapshot post,
            boolean windowClosed) {
        if (blank(currentBootId)) return null;
        Map<String, String> parsed = parse(existing);
        if (parsed == null) return null;
        if (!currentBootId.equals(parsed.get(KEY_BOOT_ID))) return null;
        String latest = verdict(post);
        String firstVerdict;
        long observations;
        boolean convergedSeen;
        boolean crashSeen;
        if (PHASE_PRE_EXEC.equals(parsed.get(KEY_PHASE))) {
            firstVerdict = latest;
            observations = 1;
            convergedSeen = CONVERGED.equals(latest);
            crashSeen = CRASH_RECOVERY.equals(latest);
        } else {
            if (!"0".equals(parsed.get(KEY_POST_SETTLED))) return null;
            firstVerdict = parsed.get(KEY_POST_FIRST_VERDICT);
            observations = numericValue(parsed.get(KEY_POST_OBSERVATIONS)) + 1;
            if (observations < 2) return null;
            convergedSeen = "1".equals(parsed.get(KEY_POST_CONVERGED_SEEN))
                    || CONVERGED.equals(latest);
            crashSeen = "1".equals(parsed.get(KEY_POST_CRASH_SEEN))
                    || CRASH_RECOVERY.equals(latest);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(KEY_SCHEMA).append('=').append(SCHEMA_VERSION).append('\n');
        sb.append(KEY_PHASE).append('=').append(PHASE_POST_EXEC).append('\n');
        sb.append(KEY_BOOT_ID).append('=').append(parsed.get(KEY_BOOT_ID)).append('\n');
        sb.append(KEY_EXEC_OUTCOME).append('=').append(parsed.get(KEY_EXEC_OUTCOME)).append('\n');
        sb.append(KEY_POST_FIRST_VERDICT).append('=').append(firstVerdict).append('\n');
        sb.append(KEY_POST_OBSERVATIONS).append('=').append(observations).append('\n');
        sb.append(KEY_POST_SETTLED).append('=').append(windowClosed ? "1" : "0").append('\n');
        sb.append(KEY_POST_CONVERGED_SEEN).append('=')
                .append(convergedSeen ? "1" : "0").append('\n');
        sb.append(KEY_POST_CRASH_SEEN).append('=').append(crashSeen ? "1" : "0").append('\n');
        for (String key : halfKeys(PRE)) {
            sb.append(key).append('=').append(parsed.get(key)).append('\n');
        }
        appendHalf(sb, POST, post);
        return sb.toString();
    }

    private static void appendHalf(StringBuilder sb, String prefix, Snapshot s) {
        sb.append(prefix).append(KEY_VERDICT).append('=').append(verdict(s)).append('\n');
        sb.append(prefix).append(KEY_READ_START_MS).append('=')
                .append(numericField(s == null ? -1L : s.readStartMs)).append('\n');
        sb.append(prefix).append(KEY_READ_END_MS).append('=')
                .append(numericField(s == null ? -1L : s.readEndMs)).append('\n');
        sb.append(prefix).append(KEY_PID).append('=')
                .append(numericField(s == null ? -1L : s.pid)).append('\n');
        sb.append(prefix).append(KEY_PROC_STARTTIME).append('=')
                .append(numericField(s == null ? -1L : s.procStarttime)).append('\n');
        for (String p : ALL_PROPERTIES) {
            sb.append(keyFor(prefix, p)).append('=')
                    .append(s == null ? UNKNOWN : s.get(p)).append('\n');
        }
    }

    /**
     * A failed reading is the literal UNKNOWN, never -1.
     *
     * The repository already learned this once, in EarlyBootProbePolicy: a
     * numeric -1 is not a second spelling of UNKNOWN, because a reader cannot
     * tell it from a value and a parser cannot refuse it.
     */
    private static String numericField(long value) {
        return value < 0 ? UNKNOWN : Long.toString(value);
    }

    private static Set<String> halfKeys(String prefix) {
        Set<String> keys = new LinkedHashSet<>();
        keys.add(prefix + KEY_VERDICT);
        keys.add(prefix + KEY_READ_START_MS);
        keys.add(prefix + KEY_READ_END_MS);
        keys.add(prefix + KEY_PID);
        keys.add(prefix + KEY_PROC_STARTTIME);
        for (String p : ALL_PROPERTIES) keys.add(keyFor(prefix, p));
        return keys;
    }

    /** What a stored record says, with every "not this" kept apart from every other. */
    public static final class Observation {
        public final String state;
        /** The verdict recorded before the teardown, or null when there is none. */
        public final String preVerdict;
        /** The LATEST post verdict, or null. */
        public final String postVerdict;
        /** The FIRST post verdict, or null. Differs from the latest when it moved. */
        public final String postFirstVerdict;
        /** How many post observations were recorded; 0 when there is no post half. */
        public final long postObservations;
        /** True when the observation WINDOW closed - not when an answer arrived. */
        public final boolean postWindowClosed;
        /** Sticky: the handshake was observed converged at least once. */
        public final boolean convergedSeen;
        /** Sticky: CrashRecovery was observed at least once. */
        public final boolean crashRecoverySeen;
        /** What this app managed to record about the exec. Never null for a parsed record. */
        public final String execOutcome;
        /** {@link #PROC_REPLACED} / {@link #PROC_SAME} / {@link #PROC_UNDECIDED}. */
        public final String processIdentity;
        /** How wide the post property sweep was, in ms; -1 when not decidable. */
        public final long postReadSpanMs;

        private Observation(String state, String preVerdict, String postVerdict,
                String postFirstVerdict, long postObservations, boolean postWindowClosed,
                boolean convergedSeen, boolean crashRecoverySeen, String execOutcome,
                String processIdentity, long postReadSpanMs) {
            this.state = state;
            this.preVerdict = preVerdict;
            this.postVerdict = postVerdict;
            this.postFirstVerdict = postFirstVerdict;
            this.postObservations = postObservations;
            this.postWindowClosed = postWindowClosed;
            this.convergedSeen = convergedSeen;
            this.crashRecoverySeen = crashRecoverySeen;
            this.execOutcome = execOutcome;
            this.processIdentity = processIdentity;
            this.postReadSpanMs = postReadSpanMs;
        }
    }

    private static Observation plain(String state) {
        return new Observation(state, null, null, null, 0, false, false, false, null,
                PROC_UNDECIDED, -1L);
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
        if (otherSchema(record)) return plain(OBS_OTHER_SCHEMA);
        Map<String, String> parsed = parse(record);
        if (parsed == null) return plain(OBS_MALFORMED);
        String exec = parsed.get(KEY_EXEC_OUTCOME);
        boolean post = PHASE_POST_EXEC.equals(parsed.get(KEY_PHASE));
        String state;
        if (blank(currentBootId) || !currentBootId.equals(parsed.get(KEY_BOOT_ID))) {
            state = OBS_STALE_BOOT;
        } else {
            state = post ? OBS_POST_EXEC : OBS_PRE_EXEC_ONLY;
        }
        if (!post) {
            return new Observation(state, parsed.get(PRE + KEY_VERDICT), null, null, 0,
                    false, false, false, exec, PROC_UNDECIDED, -1L);
        }
        long readStart = numericValue(parsed.get(POST + KEY_READ_START_MS));
        long readEnd = numericValue(parsed.get(POST + KEY_READ_END_MS));
        long span = (readStart < 0 || readEnd < 0) ? -1L : readEnd - readStart;
        return new Observation(state, parsed.get(PRE + KEY_VERDICT),
                parsed.get(POST + KEY_VERDICT), parsed.get(KEY_POST_FIRST_VERDICT),
                numericValue(parsed.get(KEY_POST_OBSERVATIONS)),
                "1".equals(parsed.get(KEY_POST_SETTLED)),
                "1".equals(parsed.get(KEY_POST_CONVERGED_SEEN)),
                "1".equals(parsed.get(KEY_POST_CRASH_SEEN)),
                exec, processIdentity(parsed), span);
    }

    /**
     * Did the restart replace the process this app runs in?
     *
     * A different pid settles it. An EQUAL pid does not: pids are reused, so the
     * same number in both halves is consistent with a replaced process that
     * happened to get it back. {@code /proc/self/stat} field 22 is the
     * disambiguator - it is the process's own start time, so two generations
     * cannot share both. Without it the answer is UNDECIDED, which is an answer.
     */
    private static String processIdentity(Map<String, String> parsed) {
        long prePid = numericValue(parsed.get(PRE + KEY_PID));
        long postPid = numericValue(parsed.get(POST + KEY_PID));
        if (prePid >= 0 && postPid >= 0 && prePid != postPid) return PROC_REPLACED;
        long preStart = numericValue(parsed.get(PRE + KEY_PROC_STARTTIME));
        long postStart = numericValue(parsed.get(POST + KEY_PROC_STARTTIME));
        if (preStart < 0 || postStart < 0) return PROC_UNDECIDED;
        if (preStart != postStart) return PROC_REPLACED;
        if (prePid < 0 || postPid < 0) return PROC_UNDECIDED;
        return PROC_SAME;
    }

    /** -1 for UNKNOWN or anything unusable; the value otherwise. */
    private static long numericValue(String raw) {
        if (raw == null || UNKNOWN.equals(raw) || blank(raw)) return -1L;
        try {
            long v = Long.parseLong(raw.trim());
            return v < 0 ? -1L : v;
        } catch (NumberFormatException e) {
            return -1L;
        }
    }

    /** A numeric field is the literal UNKNOWN or a non-negative integer. Nothing else. */
    private static boolean validNumeric(String raw) {
        if (UNKNOWN.equals(raw)) return true;
        if (blank(raw)) return false;
        try {
            return Long.parseLong(raw.trim()) >= 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /** Null-safe membership: Set.of() throws on contains(null). */
    private static boolean verdictValue(String raw) {
        return raw != null && VERDICTS.contains(raw);
    }

    private static boolean booleanField(String raw) {
        return "0".equals(raw) || "1".equals(raw);
    }

    /**
     * A well-formed record carrying a schema this build does not write.
     *
     * Read before {@link #parse}, so an older or newer format is reported as
     * itself rather than as corruption. The record outlives the app version that
     * wrote it, so those are genuinely different facts.
     */
    private static boolean otherSchema(String record) {
        if (blank(record)) return false;
        for (String raw : record.split("\\n", -1)) {
            String line = raw.trim();
            if (!line.startsWith(KEY_SCHEMA + "=")) continue;
            return !Integer.toString(SCHEMA_VERSION)
                    .equals(line.substring(KEY_SCHEMA.length() + 1));
        }
        // No schema line at all: schema 1, which this build no longer writes.
        return true;
    }

    /**
     * null on anything this build cannot fully account for.
     *
     * Strict in three directions, and the third one is the point. Structurally:
     * no unknown key, no duplicate, no missing half, no phase, verdict or exec
     * outcome outside its enumeration. Numerically: every numeric field is the
     * literal UNKNOWN or a non-negative integer, and a sweep cannot end before
     * it started. And <b>semantically: each half's stored verdict is recomputed
     * from that half's own stored properties and must match.</b>
     *
     * That last check is what makes the record evidence rather than an assertion.
     * Without it a file could say {@code pre_verdict=BOOT_HEALTH_CONVERGED} over
     * {@code pre_dev_platform_bootcomplete=0} and parse cleanly - a verdict with
     * no evidence behind it, which AGENTS.md section 2 says must refuse.
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
        if (!Integer.toString(SCHEMA_VERSION).equals(values.get(KEY_SCHEMA))) return null;
        String phase = values.get(KEY_PHASE);
        if (phase == null || !PHASES.contains(phase)) return null;
        if (blank(values.get(KEY_BOOT_ID))) return null;
        /*
         * The null check is not defensive noise. Set.of() is a null-HOSTILE
         * collection: contains(null) throws NPE rather than returning false, and
         * a record missing this key arrives here with null. A parser whose whole
         * job is to refuse must not be the thing that throws - the same reasoning
         * PostRootStatus records for String.isBlank.
         */
        String execOutcome = values.get(KEY_EXEC_OUTCOME);
        if (execOutcome == null || !EXEC_OUTCOMES.contains(execOutcome)) return null;
        boolean post = PHASE_POST_EXEC.equals(phase);
        Set<String> expected = new LinkedHashSet<>();
        expected.add(KEY_SCHEMA);
        expected.add(KEY_PHASE);
        expected.add(KEY_BOOT_ID);
        expected.add(KEY_EXEC_OUTCOME);
        if (post) {
            expected.add(KEY_POST_FIRST_VERDICT);
            expected.add(KEY_POST_OBSERVATIONS);
            expected.add(KEY_POST_SETTLED);
            expected.add(KEY_POST_CONVERGED_SEEN);
            expected.add(KEY_POST_CRASH_SEEN);
        }
        expected.addAll(halfKeys(PRE));
        if (post) expected.addAll(halfKeys(POST));
        if (!values.keySet().equals(expected)) return null;
        if (!halfIsSelfConsistent(values, PRE)) return null;
        if (post) {
            if (!halfIsSelfConsistent(values, POST)) return null;
            if (!verdictValue(values.get(KEY_POST_FIRST_VERDICT))) return null;
            if (!validNumeric(values.get(KEY_POST_OBSERVATIONS))
                    || numericValue(values.get(KEY_POST_OBSERVATIONS)) < 1) {
                return null;
            }
            if (!booleanField(values.get(KEY_POST_SETTLED))) return null;
            if (!booleanField(values.get(KEY_POST_CONVERGED_SEEN))) return null;
            if (!booleanField(values.get(KEY_POST_CRASH_SEEN))) return null;
            /*
             * The sticky flags must agree with the latest verdict they summarise.
             * A record saying "the latest reading is CONVERGED" while claiming
             * converged was never seen is not a record whose history can be read.
             */
            if (CONVERGED.equals(values.get(POST + KEY_VERDICT))
                    && !"1".equals(values.get(KEY_POST_CONVERGED_SEEN))) {
                return null;
            }
            if (CRASH_RECOVERY.equals(values.get(POST + KEY_VERDICT))
                    && !"1".equals(values.get(KEY_POST_CRASH_SEEN))) {
                return null;
            }
        }
        return values;
    }

    /**
     * A half's stored verdict, timings and identity must be consistent with the
     * half's own stored properties.
     */
    private static boolean halfIsSelfConsistent(Map<String, String> values, String prefix) {
        for (String key : List.of(prefix + KEY_READ_START_MS, prefix + KEY_READ_END_MS,
                prefix + KEY_PID, prefix + KEY_PROC_STARTTIME)) {
            if (!validNumeric(values.get(key))) return false;
        }
        long start = numericValue(values.get(prefix + KEY_READ_START_MS));
        long end = numericValue(values.get(prefix + KEY_READ_END_MS));
        // A sweep cannot finish before it began. Either end may be UNKNOWN.
        if (start >= 0 && end >= 0 && end < start) return false;
        String stored = values.get(prefix + KEY_VERDICT);
        if (!verdictValue(stored)) return false;
        Snapshot rebuilt = new Snapshot();
        for (String p : ALL_PROPERTIES) {
            String v = values.get(keyFor(prefix, p));
            if (v == null) return false;
            // put() maps a blank reading to ABSENT, so feed stored values verbatim.
            rebuilt.properties.put(p, v);
        }
        return stored.equals(verdict(rebuilt));
    }
}
