import com.polygraphene.df.reroot.AutoRootPolicy;
import com.polygraphene.df.reroot.RootEnvironment;

/**
 * Route classification, one negative case per element.
 *
 * None of these states can be produced on demand on a device: reaching
 * INCOMPLETE_DFR_BOOT costs a spent destructive transaction, FOREIGN_KSU_ACTIVE
 * needs another vendor's module loaded, and the attested states need a provider
 * that does not exist yet. A gate that cannot fail is not a gate (AGENTS.md 5),
 * so every branch is exercised here or nowhere.
 */
public final class RootEnvironmentTest {
    private static int checks;

    private static void expect(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }

    private static final String BOOT = "577fab44-5f22-4082-ac9a-616025f500fe";

    /** An observation that WOULD permit acquisition, so each mutation is the variable. */
    private static RootEnvironment.Observation clean() {
        RootEnvironment.Observation o = new RootEnvironment.Observation();
        o.bootId = BOOT;
        o.markerState = AutoRootPolicy.MARKER_ABSENT;
        o.dfrPostRootComplete = false;
        o.dfrPostRootUnreadable = false;
        o.persistentDaemon = RootEnvironment.DAEMON_ABSENT;
        o.loadedModule = RootEnvironment.MODULE_ATTESTED_NONE;
        return o;
    }

    private static RootEnvironment.Classification classify(RootEnvironment.Observation o) {
        return RootEnvironment.classify(o);
    }

    private static void refusesAcquisition(RootEnvironment.Observation o, String label) {
        expect(!classify(o).dfrAcquisitionAllowed, label);
    }

    public static void main(String[] args) {
        // --- the one permissive shape ------------------------------------------
        RootEnvironment.Classification ok = classify(clean());
        expect(RootEnvironment.STATE_NO_ACTIVE_KSU.equals(ok.state),
                "attested-clean with an absent daemon is NO_ACTIVE_KSU");
        expect(ok.dfrAcquisitionAllowed, "that state permits the acquisition attempt");
        expect(!ok.rootAvailable, "permission to attempt is not root availability");
        expect(!ok.dfrAcquired, "permission to attempt is not an acquisition");
        expect(!ok.rmgReuseAllowed, "a clean boot grants no reuse route");
        expect(!ok.persistentMigrationAllowed(), "no state permits the daemon migration");

        RootEnvironment.Observation ours = clean();
        ours.persistentDaemon = RootEnvironment.DAEMON_OURS;
        expect(classify(ours).dfrAcquisitionAllowed,
                "a persistent daemon whose bytes are ours also permits the attempt");

        // --- every daemon reading but those two refuses ------------------------
        RootEnvironment.Observation foreign = clean();
        foreign.persistentDaemon = RootEnvironment.DAEMON_FOREIGN;
        refusesAcquisition(foreign, "a foreign persistent daemon refuses acquisition");
        expect(classify(foreign).reason.contains("migration"),
                "the foreign-daemon refusal names the migration it would require");
        RootEnvironment.Observation unidentified = clean();
        unidentified.persistentDaemon = RootEnvironment.DAEMON_UNIDENTIFIED;
        refusesAcquisition(unidentified, "an unidentified persistent daemon refuses");
        RootEnvironment.Observation unknownDaemon = clean();
        unknownDaemon.persistentDaemon = RootEnvironment.DAEMON_UNKNOWN;
        refusesAcquisition(unknownDaemon,
                "an unreadable persistent daemon refuses: EACCES is not ENOENT");
        expect(classify(unknownDaemon).reason.contains("not an absent one"),
                "the unreadable refusal says so, rather than naming an errno");

        // --- module evidence: it may only ever remove permission ---------------
        RootEnvironment.Observation noAttestation = clean();
        noAttestation.loadedModule = RootEnvironment.MODULE_UNKNOWN;
        refusesAcquisition(noAttestation,
                "without a module attestation nothing may be attempted");
        expect(RootEnvironment.STATE_UNKNOWN.equals(classify(noAttestation).state),
                "no attestation is UNKNOWN, not NO_ACTIVE_KSU");
        expect(!classify(noAttestation).rmgReuseAllowed,
                "no attestation grants no reuse either");

        RootEnvironment.Observation ksuLike = clean();
        ksuLike.loadedModule = RootEnvironment.MODULE_PRESENT_UNIDENTIFIED;
        RootEnvironment.Classification foreignActive = classify(ksuLike);
        expect(RootEnvironment.STATE_FOREIGN_KSU_ACTIVE.equals(foreignActive.state),
                "a loaded module of unknown provenance is FOREIGN_KSU_ACTIVE");
        expect(!foreignActive.dfrAcquisitionAllowed,
                "no second module is loaded beside a foreign one");
        expect(!foreignActive.rmgReuseAllowed,
                "a module name is not an attestation that RMG will answer us");
        expect(!foreignActive.rootAvailable,
                "a loaded module is not proof that root is usable");
        expect(!RootEnvironment.STATE_UNKNOWN.equals(foreignActive.state),
                "'something else owns the kernel' stays distinct from 'we could not tell'");

        // --- the attested reuse route -----------------------------------------
        RootEnvironment.Observation rmg = clean();
        rmg.loadedModule = RootEnvironment.MODULE_ATTESTED_RMG;
        RootEnvironment.Classification reuse = classify(rmg);
        expect(RootEnvironment.STATE_RMG_ACTIVE_VERIFIED.equals(reuse.state),
                "an attested RMG module is RMG_ACTIVE_VERIFIED");
        expect(reuse.rmgReuseAllowed, "that state permits reuse");
        expect(reuse.rootAvailable, "and reports root as available");
        expect(RootEnvironment.PROVIDER_RMG.equals(reuse.provider), "the provider is named");
        expect(!reuse.dfrAcquired,
                "reusing another provider's root is never a DFR acquisition");
        expect(!reuse.dfrAcquisitionAllowed, "and never runs DirtyFrag");
        expect(reuse.signals().contains("DFR_ACQUISITION=NOT_ATTEMPTED"),
                "the signal triple says the acquisition was not attempted");
        expect(reuse.signals().contains("ROOT_AVAILABLE=PASS"),
                "while still reporting availability");

        // --- DFR's own completion ---------------------------------------------
        RootEnvironment.Observation done = clean();
        done.dfrPostRootComplete = true;
        done.markerState = AutoRootPolicy.MARKER_UNKNOWN; // EACCES once rooted
        RootEnvironment.Classification complete = classify(done);
        expect(RootEnvironment.STATE_DFR_ACTIVE_VERIFIED.equals(complete.state),
                "a same-boot completion is DFR_ACTIVE_VERIFIED whatever the marker says");
        expect(complete.dfrAcquired && complete.rootAvailable,
                "DFR acquired it, so both facts are true at once");
        expect(!complete.dfrAcquisitionAllowed, "and it is not run a second time");
        expect(complete.signals().contains("DFR_ACQUISITION=PASS"),
                "only DFR's own completion reports an acquisition PASS");

        RootEnvironment.Observation half = clean();
        half.loadedModule = RootEnvironment.MODULE_ATTESTED_DFR;
        RootEnvironment.Classification incomplete = classify(half);
        expect(RootEnvironment.STATE_INCOMPLETE_DFR_BOOT.equals(incomplete.state),
                "our module loaded without a completion is INCOMPLETE_DFR_BOOT");
        expect(!incomplete.dfrAcquisitionAllowed, "which refuses a second bootstrap");
        expect(!incomplete.rootAvailable, "and claims no root");

        // --- marker and record states -----------------------------------------
        RootEnvironment.Observation armed = clean();
        armed.markerState = AutoRootPolicy.MARKER_PRESENT;
        refusesAcquisition(armed, "an armed marker refuses a second run");
        expect(RootEnvironment.STATE_INCOMPLETE_DFR_BOOT.equals(classify(armed).state),
                "an armed marker with no module loaded is an incomplete boot");
        RootEnvironment.Observation markerUnknown = clean();
        markerUnknown.markerState = AutoRootPolicy.MARKER_UNKNOWN;
        refusesAcquisition(markerUnknown,
                "an undeterminable marker is not an assumed clean boot");
        RootEnvironment.Observation recordUnreadable = clean();
        recordUnreadable.dfrPostRootUnreadable = true;
        refusesAcquisition(recordUnreadable,
                "an unreadable completion record is not an unrun boot");
        expect(RootEnvironment.STATE_UNKNOWN.equals(classify(recordUnreadable).state),
                "and it classifies as UNKNOWN rather than NO_ACTIVE_KSU");

        // --- degenerate inputs -------------------------------------------------
        RootEnvironment.Observation noBoot = clean();
        noBoot.bootId = "";
        refusesAcquisition(noBoot, "no boot_id refuses: no evidence can be bound to a boot");
        RootEnvironment.Observation nullBoot = clean();
        nullBoot.bootId = null;
        refusesAcquisition(nullBoot, "a null boot_id refuses rather than throwing");
        RootEnvironment.Observation blankBoot = clean();
        blankBoot.bootId = "   ";
        refusesAcquisition(blankBoot, "a blank boot_id refuses");
        RootEnvironment.Classification none = RootEnvironment.classify(null);
        expect(!none.dfrAcquisitionAllowed && !none.rmgReuseAllowed
                        && !none.rootAvailable && !none.dfrAcquired,
                "a null observation permits nothing");
        expect(RootEnvironment.STATE_UNKNOWN.equals(none.state),
                "a null observation is UNKNOWN");

        // --- an unrecognised enum value is a refusal, never a pass -------------
        RootEnvironment.Observation bogusModule = clean();
        bogusModule.loadedModule = 9999;
        refusesAcquisition(bogusModule, "an unrecognised module value refuses");
        RootEnvironment.Observation bogusDaemon = clean();
        bogusDaemon.persistentDaemon = 9999;
        refusesAcquisition(bogusDaemon, "an unrecognised daemon value refuses");
        RootEnvironment.Observation bogusMarker = clean();
        bogusMarker.markerState = 9999;
        refusesAcquisition(bogusMarker, "an unrecognised marker value refuses");

        // --- the default-constructed observation permits nothing ---------------
        RootEnvironment.Classification fresh =
                RootEnvironment.classify(new RootEnvironment.Observation());
        expect(!fresh.dfrAcquisitionAllowed && !fresh.rmgReuseAllowed,
                "a fresh observation, filled in by nobody, permits nothing");

        System.out.println("RootEnvironmentTest: " + checks + "/" + checks + " passed");
    }
}
