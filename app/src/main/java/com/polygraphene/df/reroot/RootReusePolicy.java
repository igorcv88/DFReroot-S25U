package com.polygraphene.df.reroot;

/**
 * The result of the RMG route in Run All.
 *
 * The companion's attestation executes a real, bounded `su -c` operation as
 * root (uid 0, a root-only hash and a managerless kernel-contract round-trip).
 * Successful reuse is therefore an executed root operation, rather than a
 * passive module-name or `/proc/modules` observation. This is NOT DFR's own
 * DirtyFrag acquisition and must never qualify Auto Root or publish
 * POST_ROOT_COMPLETE.
 */
public final class RootReusePolicy {
    private RootReusePolicy() {}

    public static boolean succeeded(RootEnvironment.Classification verdict) {
        return verdict != null
                && RootEnvironment.STATE_RMG_ACTIVE_VERIFIED.equals(verdict.state)
                && RootEnvironment.PROVIDER_RMG.equals(verdict.provider)
                && verdict.rootAvailable
                && verdict.rmgReuseAllowed
                && !verdict.dfrAcquired
                && !verdict.dfrAcquisitionAllowed
                && !verdict.persistentMigrationAllowed();
    }
}
