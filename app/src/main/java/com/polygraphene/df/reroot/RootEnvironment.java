package com.polygraphene.df.reroot;

/**
 * Which root provider, if any, is established in THIS boot - and therefore
 * which route the app is allowed to take.
 *
 * <h2>Why this class exists</h2>
 *
 * The chain had exactly one shape: "the app must acquire root", so every run
 * went through DirtyFrag and every run ended by having the DFR daemon take over
 * the persistent KernelSU installation at {@code /data/adb/ksud}. On a device
 * that already carries a working foreign KernelSU pair (the owner's RMGLabs
 * install) that is not one question but three, and collapsing them is what
 * produced the 2026-11-12 OWO failure:
 *
 * <ul>
 *   <li><b>Is root available?</b> It was - RMGLabs had it.</li>
 *   <li><b>Did DFR acquire it?</b> No, and it must never claim otherwise.</li>
 *   <li><b>May DFR take over the persistent daemon?</b> A separate, destructive
 *       question that an ordinary run has no business answering.</li>
 * </ul>
 *
 * The app answered the third one from {@code u:r:system_server:s0} with an
 * {@code lstat("/data/adb/ksud")} and received EACCES, so the run refused
 * before DirtyFrag with a reason that named an errno rather than a state. That
 * refusal was correct (an unreadable artefact is never an absent one, AGENTS.md
 * 3.3) and it was asked in the wrong place: the question only matters for the
 * operation that would replace those bytes, and the process asking could not
 * obtain the evidence (the same shape as the 3.5.1 defect).
 *
 * <h2>What this class is, and is not</h2>
 *
 * It is pure: observations in, a classification out, no I/O, no Android. That
 * is deliberate (AGENTS.md 5) - every state below is unreachable on demand on a
 * device, because producing one costs a reboot and sometimes the device's root
 * session, so the only place they can all be exercised is a host test.
 *
 * It decides <b>permission to attempt</b>, never success. It cannot grant root,
 * cannot use root, and every boundary that already refuses - the marker probe,
 * the staging digest, the daemon's own ownership gate, the post-root contract,
 * the transport_fix marker - still runs afterwards and still refuses on its own
 * evidence. A permissive answer here only means "this route is not already
 * known to be wrong".
 *
 * <h2>The asymmetry that keeps it honest</h2>
 *
 * Evidence that a foreign KernelSU is loaded can <b>remove</b> permission to
 * run the acquisition route. The same evidence can never <b>grant</b> the reuse
 * route: a module name read out of {@code /proc/modules} says something is
 * loaded, not whose it is or that it will answer us. Granting reuse needs a
 * positive attestation from an authorized provider, which no component running
 * at {@code u:r:system_server:s0} can produce today - this app's own native
 * library cannot even be mapped executable in that domain. So
 * {@link #STATE_RMG_ACTIVE_VERIFIED} is modelled, tested and currently
 * unreachable, and it stays unreachable until the authorized companion
 * transport exists. An unreachable state is the correct cost of missing
 * evidence (AGENTS.md 2); inferring the provider from a name would be the
 * absence-as-permission defect this repository exists to prevent.
 */
public final class RootEnvironment {

    private RootEnvironment() {}

    // --- what is known about the persistent daemon entry ---------------------
    /** The lookup did not answer (EACCES, EPERM, I/O). Never absence. */
    public static final int DAEMON_UNKNOWN = 0;
    /** Provably absent: ENOENT, and nothing else. */
    public static final int DAEMON_ABSENT = 1;
    /** Present, and its bytes match this profile's pinned DFR daemon. */
    public static final int DAEMON_OURS = 2;
    /** Present, readable, and its identity is not ours. A hard fact. */
    public static final int DAEMON_FOREIGN = 3;
    /** Present, but its identity could not be established (size/hash unread). */
    public static final int DAEMON_UNIDENTIFIED = 4;

    // --- what is known about the LOADED kernel module ------------------------
    /**
     * No evidence either way.
     *
     * This covers two different readings, and the caller must keep them apart
     * in its log (AGENTS.md 3.7): {@code /proc/modules} unreadable, and
     * {@code /proc/modules} read with no KernelSU-like entry in it. The second
     * is not "no module is loaded" - a module that hides itself from that file
     * reads exactly the same - so neither may promote anything here.
     */
    public static final int MODULE_UNKNOWN = 0;
    /** A KernelSU-like module is loaded; whose it is was not established. */
    public static final int MODULE_PRESENT_UNIDENTIFIED = 1;
    /** An authorized provider attested that the loaded module is the DFR pair. */
    public static final int MODULE_ATTESTED_DFR = 2;
    /** An authorized provider attested that the loaded module is the RMG pair. */
    public static final int MODULE_ATTESTED_RMG = 3;
    /** An authorized provider attested that NO KernelSU module is loaded. */
    public static final int MODULE_ATTESTED_NONE = 4;

    // --- states --------------------------------------------------------------
    /** RMGLabs is active and proven usable. Reuse it; never run DirtyFrag. */
    public static final String STATE_RMG_ACTIVE_VERIFIED = "RMG_ACTIVE_VERIFIED";
    /** DFR completed its own same-boot post-root contract. Reuse that session. */
    public static final String STATE_DFR_ACTIVE_VERIFIED = "DFR_ACTIVE_VERIFIED";
    /** Positively attested: nothing is loaded. The only state acquisition may run in. */
    public static final String STATE_NO_ACTIVE_KSU = "NO_ACTIVE_KSU";
    /** A DFR run armed hooks or loaded its module and did not complete. */
    public static final String STATE_INCOMPLETE_DFR_BOOT = "INCOMPLETE_DFR_BOOT";
    /**
     * A KernelSU that is not ours is loaded.
     *
     * Kept apart from {@link #STATE_UNKNOWN} on purpose: "something else owns
     * the kernel side" and "we could not tell" lead the owner to different next
     * steps, and only the first one justifies the invariant that no second
     * module may be loaded beside it (laudo 7.3).
     */
    public static final String STATE_FOREIGN_KSU_ACTIVE = "FOREIGN_KSU_ACTIVE";
    /** Identity or state not verifiable. Refuses every non-observational route. */
    public static final String STATE_UNKNOWN = "UNKNOWN";

    // --- providers -----------------------------------------------------------
    public static final String PROVIDER_RMG = "RMG";
    public static final String PROVIDER_DFR = "DFR";
    public static final String PROVIDER_FOREIGN = "FOREIGN";
    public static final String PROVIDER_NONE = "NONE";
    public static final String PROVIDER_UNKNOWN = "UNKNOWN";

    /** Non-destructive readings taken by the caller, each already tri-stated. */
    public static final class Observation {
        /** {@code /proc/sys/kernel/random/boot_id}; blank means unreadable. */
        public String bootId = "";
        /** One of {@link AutoRootPolicy#MARKER_PRESENT} / ABSENT / UNKNOWN. */
        public int markerState = AutoRootPolicy.MARKER_UNKNOWN;
        /** A {@link PostRootStatus} verdict for THIS boot said complete. */
        public boolean dfrPostRootComplete = false;
        /**
         * The completion record could not be read, or its presence not
         * determined. Never folded into "absent" (PR #93's correction).
         */
        public boolean dfrPostRootUnreadable = false;
        /** One of the {@code DAEMON_*} constants. */
        public int persistentDaemon = DAEMON_UNKNOWN;
        /** One of the {@code MODULE_*} constants. */
        public int loadedModule = MODULE_UNKNOWN;
        /**
         * SELinux was observed Enforcing by BOTH the authorized provider (as
         * root, at the instant of the attestation) and this process's own live
         * read.
         *
         * A separate element on purpose, and required for the reuse route. Two
         * reasons. It is not evidence about the module - a permissive kernel
         * would answer the contract ioctl exactly the same - so folding it into
         * the attestation would be 3.7's collapse. And it is this project's
         * invariant 11: an operation concludes with SELinux Enforcing, so
         * offering a route while the device is permissive would be offering to
         * act on a state nobody has explained. Unreadable on either side is
         * false, because neither reader may assume the other's answer.
         */
        public boolean selinuxEnforcing = false;
    }

    /** What the caller may do, and why. Each field is a separate fact. */
    public static final class Classification {
        public final String state;
        public final String provider;
        /**
         * A provider's root is established in this boot on evidence this build
         * accepts. It is NOT a claim that this app can issue a root command:
         * that needs a transport, and each transport keeps its own gate.
         */
        public final boolean rootAvailable;
        /** DFR itself acquired root in this boot. Never true for a foreign provider. */
        public final boolean dfrAcquired;
        /** The DirtyFrag acquisition route may be ATTEMPTED. */
        public final boolean dfrAcquisitionAllowed;
        /** The RMG reuse route may be attempted (needs an attested provider). */
        public final boolean rmgReuseAllowed;
        public final String reason;

        private Classification(String state, String provider, boolean rootAvailable,
                boolean dfrAcquired, boolean dfrAcquisitionAllowed,
                boolean rmgReuseAllowed, String reason) {
            this.state = state;
            this.provider = provider;
            this.rootAvailable = rootAvailable;
            this.dfrAcquired = dfrAcquired;
            this.dfrAcquisitionAllowed = dfrAcquisitionAllowed;
            this.rmgReuseAllowed = rmgReuseAllowed;
            this.reason = reason;
        }

        /**
         * Taking over {@code /data/adb/ksud} is a migration, not a run.
         *
         * A constant, and deliberately not derived from any field of
         * {@link Observation}: the laudo's 4.5 requires an explicit owner
         * request, a verified recovery copy, a restore path independent of the
         * new KernelSU and a proven rollback - none of which exist in this
         * build. A boolean input here would be a switch an agent could flip
         * from data, which is the shape AGENTS.md 3.6 forbids. When the
         * migration is implemented it gets its own entry point and its own
         * evidence; it never becomes a parameter of an ordinary run.
         */
        public boolean persistentMigrationAllowed() {
            return false;
        }

        /** The signal triple the laudo's 4.2 requires, never collapsed into one. */
        public String signals() {
            return "ROOT_PROVIDER=" + provider
                    + " ROOT_AVAILABLE=" + (rootAvailable ? "PASS" : "FAIL")
                    + " DFR_ACQUISITION=" + (dfrAcquired ? "PASS" : "NOT_ATTEMPTED");
        }
    }

    private static Classification of(String state, String provider, boolean rootAvailable,
            boolean dfrAcquired, boolean acquisitionAllowed, boolean reuseAllowed,
            String reason) {
        return new Classification(state, provider, rootAvailable, dfrAcquired,
                acquisitionAllowed, reuseAllowed, reason);
    }

    /**
     * Classify the boot. Every unresolved element costs permission, never grants it.
     *
     * The order of the branches is the order in which evidence is decisive, and
     * it matters: an attested provider settles the question whatever the marker
     * probe says, because once root is established on this firmware the
     * {@code /dev/df*} lookups answer EACCES rather than ENOENT and the probe
     * stops being able to speak (AGENTS.md 3.11).
     */
    public static Classification classify(Observation o) {
        if (o == null) {
            return of(STATE_UNKNOWN, PROVIDER_UNKNOWN, false, false, false, false,
                    "no observation was supplied");
        }
        if (o.bootId == null || o.bootId.trim().isEmpty()) {
            return of(STATE_UNKNOWN, PROVIDER_UNKNOWN, false, false, false, false,
                    "current boot_id unreadable; no per-boot evidence can be bound");
        }

        /*
         * DFR's own completion is the strongest evidence this build has, and it
         * is the only one that is self-attesting: the record is written by our
         * daemon, names this boot, and has already been through the full
         * PostRootStatus contract in the caller.
         */
        if (o.dfrPostRootComplete) {
            return of(STATE_DFR_ACTIVE_VERIFIED, PROVIDER_DFR, true, true, false, false,
                    "DFR completed its same-boot post-root contract in this boot;"
                            + " reuse that session and do not run the chain again");
        }

        switch (o.loadedModule) {
            case MODULE_ATTESTED_RMG:
                if (!o.selinuxEnforcing) {
                    /*
                     * The provider attested the pair and SELinux is not
                     * Enforcing on both readings. That is not a reuse route: it
                     * is a device in a state this build cannot account for, and
                     * the attestation does not speak to it either way.
                     */
                    return of(STATE_UNKNOWN, PROVIDER_RMG, false, false, false, false,
                            "the RMG pair was attested but SELinux was not observed"
                                    + " Enforcing by both the provider and this process;"
                                    + " refusing every route until that is explained");
                }
                return of(STATE_RMG_ACTIVE_VERIFIED, PROVIDER_RMG, true, false, false, true,
                        "an authorized provider attested the loaded module is the RMG"
                                + " pair, with SELinux Enforcing on both readings; reusing"
                                + " it and not running DirtyFrag");
            case MODULE_ATTESTED_DFR:
                /*
                 * Our module is loaded and the contract did not complete. The
                 * kernel side is already modified, so a second bootstrap in
                 * this boot would write over its own work; recovery is the
                 * owner's decision, not a retry.
                 */
                return of(STATE_INCOMPLETE_DFR_BOOT, PROVIDER_DFR, false, false, false, false,
                        "the DFR module is loaded but its post-root contract did not"
                                + " complete; refusing a second bootstrap in this boot");
            case MODULE_PRESENT_UNIDENTIFIED:
                return of(STATE_FOREIGN_KSU_ACTIVE, PROVIDER_FOREIGN, false, false, false, false,
                        "a KernelSU-like module is loaded and its provenance was not"
                                + " established; refusing to load a second one and"
                                + " refusing to claim its root");
            case MODULE_ATTESTED_NONE:
                break; // the only path that may reach the acquisition route
            case MODULE_UNKNOWN:
            default:
                /*
                 * The common reading on the owner's device today, and the
                 * honest one: nothing in system_server can attest what the
                 * kernel is running. A marker or a module that merely LOOKS
                 * absent is not evidence of absence.
                 */
                return of(STATE_UNKNOWN, PROVIDER_UNKNOWN, false, false, false, false,
                        "no attestation of the loaded KernelSU module is obtainable from"
                                + " this process; refusing both routes until an authorized"
                                + " provider can answer");
        }

        // --- MODULE_ATTESTED_NONE from here down -----------------------------
        if (o.markerState == AutoRootPolicy.MARKER_PRESENT) {
            return of(STATE_INCOMPLETE_DFR_BOOT, PROVIDER_NONE, false, false, false, false,
                    "/dev/df or a stage marker exists while no module is loaded: a run"
                            + " in this boot armed hooks and did not finish. Only a hard"
                            + " reboot clears them");
        }
        if (o.markerState != AutoRootPolicy.MARKER_ABSENT) {
            return of(STATE_UNKNOWN, PROVIDER_NONE, false, false, false, false,
                    "whether /dev/df or a stage marker exists could not be determined"
                            + " (not ENOENT); refusing rather than assuming a clean boot");
        }
        if (o.dfrPostRootUnreadable) {
            /*
             * The record may exist and say this boot already ran. An
             * unreadable artefact changes which proof is required, never
             * whether one is required (AGENTS.md 3.3) - and here there is no
             * second proof, so it refuses.
             */
            return of(STATE_UNKNOWN, PROVIDER_NONE, false, false, false, false,
                    "the DFR completion record could not be read or its presence"
                            + " determined; refusing to treat that as an unrun boot");
        }
        switch (o.persistentDaemon) {
            case DAEMON_ABSENT:
            case DAEMON_OURS:
                return of(STATE_NO_ACTIVE_KSU, PROVIDER_NONE, false, false, true, false,
                        "no module is loaded, no marker is armed and the persistent"
                                + " daemon is absent or ours; the DFR acquisition route"
                                + " may be attempted and every later gate still applies");
            case DAEMON_FOREIGN:
                return of(STATE_NO_ACTIVE_KSU, PROVIDER_NONE, false, false, false, false,
                        "the persistent KernelSU daemon belongs to another provider;"
                                + " acquiring root here would require taking it over,"
                                + " which is a separate migration and is not implemented");
            case DAEMON_UNIDENTIFIED:
                return of(STATE_NO_ACTIVE_KSU, PROVIDER_NONE, false, false, false, false,
                        "a persistent KernelSU daemon exists and its identity could not"
                                + " be established; refusing before the DirtyFrag hop");
            case DAEMON_UNKNOWN:
            default:
                return of(STATE_NO_ACTIVE_KSU, PROVIDER_NONE, false, false, false, false,
                        "the persistent KernelSU daemon entry could not be inspected;"
                                + " an unreadable path is not an absent one");
        }
    }
}
