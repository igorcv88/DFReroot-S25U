package com.polygraphene.df.reroot;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure policy for "Apply Modules (Soft Reboot)".
 *
 * A soft reboot re-applies the KernelSU module lifecycle WITHOUT restarting the
 * kernel. This is not an inference about what a zygote restart happens to do: at
 * the pinned KernelSU revision this pair is built from
 * (932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e), {@code soft_reboot()} in
 * {@code userspace/ksud/src/init_event.rs} reads, in order:
 *
 * <pre>
 *   ensure_uapi_version_matched()   -- see the trap below
 *   daemonize_with(switch_mnt_ns(1), chdir("/"))
 *   reset_boot_completed()
 *   run_stage("emulated-soft-reboot")
 *   stop
 *   on_post_data_fs()               -- the module lifecycle, re-run
 *   start
 *   on_services()
 *   wait_for_boot_completed()
 *   on_boot_completed()
 * </pre>
 *
 * So the worker daemonises into PID 1's mount namespace BEFORE `stop`, which is
 * what lets it outlive the userspace it tears down, and `on_post_data_fs()` is
 * called again - module dirs, post-fs-data.d scripts, sepolicy rules, system.prop
 * and the mount stages included. The kernel, `kernelsu.ko` and `boot_id` are all
 * untouched, so losing a `su` shell that was open across `stop` is not losing
 * root. That was read out of that revision's source, not assumed from behaviour.
 *
 * <h2>The trap: exit status 0 does not mean the soft reboot happened</h2>
 *
 * When {@code ensure_uapi_version_matched()} fails, {@code soft_reboot()} logs and
 * returns {@code Ok(())} - it SKIPS the soft reboot and the process still exits
 * successfully. And on the success path it daemonises, so the parent also exits 0
 * immediately. Exit 0 is therefore ambiguous by construction and is never treated
 * here as evidence of anything.
 *
 * What removes the ambiguity is evidence this policy already demands for its own
 * reasons: a valid same-boot post-root record asserts {@code uapi_version=2},
 * which is the very comparison {@code ensure_uapi_version_matched()} makes. Same
 * boot, same kernel, same UAPI - so a record that satisfies
 * {@link PostRootStatus} means the skip branch cannot be the one taken. The
 * caller still reports DISPATCHED rather than applied, because `stop` kills the
 * process that would have observed the outcome.
 *
 * <h2>What this must never become</h2>
 *
 * A re-run of the chain. This decides whether an ALREADY-ROOTED boot may ask the
 * resident KernelSU to re-apply modules; it has no path to the exploit, and
 * {@code tools/profile_binding_audit.py} fails if the receiver that consumes it
 * ever gains one. The residual risk the owner accepted is a soft-reboot-specific
 * failure on this firmware (a bad `stop`/`start`, a metamodule mount), which must
 * surface as its own post-root failure and never authorise another exploit run.
 */
public final class SoftRebootPolicy {

    /** Phase written when this boot's one permitted attempt is claimed/spent. */
    public static final String PHASE_CLAIMED = "CLAIMED";

    private static final Set<String> LOCK_KEYS =
            Set.of("boot_id", "phase", "claimed_at_ms");
    private static final Set<String> LEGACY_LOCK_KEYS =
            Set.of("boot_id", "phase", "dispatched_at_ms");
    private static final Set<String> ALL_LOCK_KEYS =
            Set.of("boot_id", "phase", "claimed_at_ms", "dispatched_at_ms");

    private SoftRebootPolicy() {}

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** One candidate binary: where it is, and the digest actually read from it. */
    public static final class Candidate {
        public final String path;
        /** null when the file is absent or could not be hashed - never "" for that. */
        public final String sha256;

        public Candidate(String path, String sha256) {
            this.path = path;
            this.sha256 = sha256;
        }
    }

    public static final class Inputs {
        public String currentBootId;
        /** The boot the notification action was created for. */
        public String requestBootId;
        public String postRootRecord;
        public int liveSelinux = -1;
        /** null when no attempt was claimed in any boot; never "" for that. */
        public String lockRecord;
        public String pinnedKsudSha256;
        /**
         * The Samsung boot-health verdict for the current moment, from
         * {@link SoftRebootHealthPolicy#verdict}.
         *
         * Defaults to the refusing value for the same reason {@code liveSelinux}
         * defaults to -1: a caller that forgets to supply it must be refused,
         * never permitted. Only {@link SoftRebootHealthPolicy#CONVERGED} passes.
         */
        public String bootHealthVerdict = SoftRebootHealthPolicy.HEALTH_UNKNOWN;
        /** In preference order. The first digest match wins; no match refuses. */
        public final List<Candidate> candidates = new ArrayList<>();
    }

    public static final class Decision {
        public final boolean allow;
        public final String reason;
        /** The binary to invoke. Non-null only when {@link #allow} is true. */
        public final String binaryPath;

        Decision(boolean allow, String reason, String binaryPath) {
            this.allow = allow;
            this.reason = reason;
            this.binaryPath = binaryPath;
        }
    }

    private static Decision refuse(String reason) {
        return new Decision(false, reason, null);
    }

    /**
     * Everything decidable WITHOUT a root shell.
     *
     * Split out because the candidate digests cannot be read by this app at all.
     * The chain consumes the staged daemon and installs it at {@code /data/adb/ksud}
     * - observed on ZZIC: after a successful run the staged path is gone and
     * {@code /data/adb} is {@code drwx------ root root u:object_r:adb_data_file:s0},
     * so uid 1000 cannot even traverse it. The digests therefore have to be taken
     * through the privileged shell, which means the shell has to be obtained first,
     * which means the cheap boot-scope and post-root refusals must run before that
     * or a stale notification would spawn a root shell just to be refused.
     *
     * Returns null when nothing here refuses, or the refusal.
     */
    public static Decision precheck(Inputs in) {
        Decision d = preCandidateChecks(in);
        return d != null ? d : new Decision(true, "SOFT_REBOOT_PRECHECK=PASS", null);
    }

    public static Decision evaluate(Inputs in) {
        Decision refusal = preCandidateChecks(in);
        if (refusal != null) return refusal;
        return selectBinary(in);
    }

    private static Decision preCandidateChecks(Inputs in) {
        if (in == null) return refuse("no inputs");
        if (blank(in.currentBootId)) return refuse("current boot_id is unavailable");
        if (blank(in.requestBootId)) {
            return refuse("the request carries no boot_id; a soft reboot request that"
                    + " cannot be placed in a boot is refused");
        }
        /*
         * A notification is a durable object and this action is boot-scoped
         * evidence (AGENTS.md 3.8). Acting on a request minted in another boot
         * would mean asking an unrooted boot to re-apply modules.
         */
        if (!in.requestBootId.equals(in.currentBootId)) {
            return refuse("the request belongs to boot " + in.requestBootId
                    + " but this is boot " + in.currentBootId);
        }

        /*
         * Root has to be established IN THIS BOOT, by our own chain, with the
         * record this build already trusts for exactly that question. Reusing
         * PostRootStatus here is deliberate: a second, looser notion of "rooted"
         * is how the two would drift apart.
         */
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.postRootRecord)) {
            return refuse("the post-root record exists but could not be read");
        }
        PostRootStatus.Verdict verdict =
                PostRootStatus.evaluate(in.postRootRecord, in.currentBootId, in.liveSelinux);
        if (!verdict.complete) {
            return refuse("no verified same-boot post-root state (" + verdict.reason
                    + "); a soft reboot is only offered to a boot this build rooted");
        }

        /*
         * Idempotent per boot. A second soft reboot issued while the first is
         * tearing userspace down is the one way a well-behaved button becomes a
         * boot loop, and the notification's action is trivially tappable twice.
         *
         * This check alone does NOT serialise two concurrent taps: it reads a
         * durable record, so two threads that arrive together both see no lock. The
         * caller closes that with an in-process compare-and-set before it gets here,
         * and the claim it writes afterwards is taken exclusively
         * (`AutoRootStore.claimSoftReboot`). What this check covers is the case the
         * record exists for - a process that restarted within the same boot, where
         * no in-memory guard survives.
         */
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.lockRecord)) {
            return refuse("the soft-reboot lock exists but could not be read;"
                    + " refusing rather than dispatching a second one");
        }
        if (!blank(in.lockRecord)) {
            Map<String, String> lock = parse(in.lockRecord);
            if (lock == null) {
                return refuse("the soft-reboot lock is unreadable; refusing rather than"
                        + " dispatching a second one");
            }
            if (in.currentBootId.equals(lock.get("boot_id"))) {
                return refuse("this boot's soft-reboot attempt is already claimed/spent ("
                        + lock.get("phase") + ")");
            }
            // A lock naming another boot is last boot's record and locks nothing.
        }

        /*
         * The Samsung boot-health handshake, and the one gate on this action that
         * came out of a physical failure rather than a reading of source.
         *
         * On 2026-10-01 this dispatch worked: ksud ran, the framework restarted,
         * the UI came back. Minutes later the device full-rebooted with
         * `reboot,rollback_staged_install(bootchecker_timeout)` after CrashRecovery
         * classified the stall as NATIVE_CRASH. The firmware's own
         * /system/etc/init/bootchecker.rc zeroes `dev.platform_bootcomplete` and
         * restarts its boot watchdog on `init.svc.zygote=restarting`, which an
         * emulated soft reboot necessarily produces.
         *
         * This refusal does NOT fix that, and must never be described as if it
         * did - the trigger is in the firmware's init rc and the property that
         * clears it is written by a daemon outside this app.
         *
         * And it is worth being exact about what it adds, because an earlier
         * version of this comment claimed more than it does. It said this stops a
         * SECOND userspace teardown stacked on an unconverged handshake - but the
         * per-boot soft-reboot lock above ALREADY makes a second DFR Apply Modules
         * in one boot impossible, so that was a job already done. What this gate
         * actually adds is refusing the FIRST attempt in a boot whose health is
         * already bad for some other reason: an unrelated framework restart, a
         * rollback already in flight, a watchdog still waiting. On a healthy full
         * boot every element reads positive and this costs nothing.
         *
         * BOOT_HEALTH_UNKNOWN refuses for AGENTS.md section 2's reason: the worst
         * outcome of this operation is an unplanned full reboot with a staged
         * rollback, so a state that could not be read is not permission to add a
         * teardown to it.
         *
         * BOOT_HEALTH_NOT_APPLICABLE passes, and has to. This is a Samsung
         * mechanism, and this action is reachable off-target: an unrelated device
         * running the bundled daemon can satisfy PostRootStatus, and AGENTS.md
         * section 1 says such a device takes the unchanged upstream path. A
         * Samsung-only gate applied unconditionally would therefore refuse Apply
         * Modules on every device but this one. The policy only reaches that
         * verdict when AOSP itself calls the boot complete AND the whole OEM
         * mechanism is positively unset, which cannot happen on the pinned
         * target - a partially present mechanism is PENDING, and an unreadable
         * one is UNKNOWN. Both of those still refuse.
         */
        if (!SoftRebootHealthPolicy.permitsDispatch(in.bootHealthVerdict)) {
            return refuse("the firmware's boot-health handshake is "
                    + (in.bootHealthVerdict == null
                            ? SoftRebootHealthPolicy.HEALTH_UNKNOWN : in.bootHealthVerdict)
                    + "; a soft reboot is only dispatched from a boot this firmware"
                    + " itself considers complete. A full reboot re-applies modules"
                    + " through post-fs-data");
        }
        return null;
    }

    /*
         * Bind the claim to bytes (AGENTS.md 3.5). The binary that performs this
         * is chosen by DIGEST, never by path, because on this device
         * /data/adb/ksud is routinely replaced by the root manager's own build:
     * it has been observed holding 99aaa607... (4,892,712 bytes, byte-identical to
     * the manager APK's libksud.so) at one point and the pinned DFR daemon
     * 14fb9eaf... (6,670,272 bytes) at another, on the same device. Invoking
     * whatever happens to sit at that path would be handing a privileged lifecycle
     * operation to an unidentified binary.
     */
    private static Decision selectBinary(Inputs in) {
        if (blank(in.pinnedKsudSha256)) {
            return refuse("no pinned ksud digest to compare against");
        }
        String pinned = in.pinnedKsudSha256.trim().toLowerCase();
        StringBuilder found = new StringBuilder();
        for (Candidate c : in.candidates) {
            if (c == null || blank(c.path)) continue;
            if (c.sha256 == null) {
                found.append(" ").append(c.path).append("=unreadable");
                continue;
            }
            String actual = c.sha256.trim().toLowerCase();
            if (pinned.equals(actual)) {
                return new Decision(true,
                        "SOFT_REBOOT_PRECHECK=PASS using " + c.path
                                + " (digest matches the pinned ksud)", c.path);
            }
            found.append(" ").append(c.path).append("=").append(actual);
        }
        return refuse("no candidate ksud matches the pinned digest " + pinned
                + "; found:" + (found.length() == 0 ? " none" : found.toString()));
    }

    /** null on anything this build cannot fully account for. */
    private static Map<String, String> parse(String record) {
        if (blank(record)) return null;
        Map<String, String> values = new HashMap<>();
        for (String raw : record.split("\\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int separator = line.indexOf('=');
            if (separator <= 0 || separator == line.length() - 1) return null;
            String key = line.substring(0, separator);
            if (!ALL_LOCK_KEYS.contains(key)) return null;
            if (values.putIfAbsent(key, line.substring(separator + 1)) != null) return null;
        }
        if (values.keySet().equals(LOCK_KEYS)) {
            if (!PHASE_CLAIMED.equals(values.get("phase"))) return null;
        } else if (!values.keySet().equals(LEGACY_LOCK_KEYS)) {
            return null;
        }
        return values;
    }

    /** The lock record, in the one format {@link #parse} accepts. */
    public static String formatLock(String bootId, long claimedAtMs) {
        return "boot_id=" + bootId + "\n"
                + "phase=" + PHASE_CLAIMED + "\n"
                + "claimed_at_ms=" + claimedAtMs + "\n";
    }
}
