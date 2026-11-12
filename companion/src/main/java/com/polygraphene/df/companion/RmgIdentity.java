package com.polygraphene.df.companion;

/**
 * What this build believes the RMG pair on the target firmware is. Pure pins.
 *
 * The digest and size are the ones read from the owner's device through a root
 * shell on 2026-11-12 and recorded in
 * {@code docs/S25U_DZIF_OWO_COMPATIBILITY.md}. They are a pin, not a discovery:
 * a daemon whose bytes differ is a different daemon, and this companion says so
 * rather than attesting whatever it happens to find.
 */
public final class RmgIdentity {

    private RmgIdentity() {}

    /** The global path both providers' installations claim. */
    public static final String KSUD_PATH = "/data/adb/ksud";

    /** RMG managerless daemon, S938BXXUCDZIF / OWO. */
    public static final String RMG_KSUD_SHA256 =
            "95b2cc363f420b075c1b1301cb959d29d2cd5845372eb3e89b849d020981d8a5";
    public static final long RMG_KSUD_SIZE = 5797976L;

    /**
     * The contract line {@code ksud profile status} prints on the paired
     * managerless build.
     *
     * Its presence is the attestation that matters. {@code status} runs
     * {@code ensure_uapi_version_matched()} and then {@code ioctl::contract(0)}
     * — ioctl {@code 0xc0104b1e}, revision 1, {@code profile_size} 784,
     * operation 0 which performs no write — and fails with "paired managerless
     * kernel required" when the LOADED module does not implement it. Upstream
     * KernelSU does not. So a well-formed status line is evidence about the
     * module the kernel is actually running, which a name in
     * {@code /proc/modules} is not.
     */
    public static final String STATUS_PREFIX = "package=";

    /** The module name both pairs load under; never an identity on its own. */
    public static final String KSU_MODULE_NAME = "kernelsu";
}
