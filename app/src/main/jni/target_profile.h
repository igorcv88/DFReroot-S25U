/*
 * target_profile.h - explicit target/profile abstraction for DFReroot.
 *
 * DESIGN GOAL (fail-closed): the upstream generic behaviour (kernel-family
 * selection of dirtyfrag-android<rel>-<maj>.<min>.ko) is preserved verbatim
 * for every device that is NOT the exact Galaxy S25 Ultra ZZIC target. For
 * that one firmware (SM-S938B / pa3q / S938BXXUCZZIC), a dedicated profile
 * demands an *exact* identity match and lets Gate B validate kernel/userspace
 * artefacts before any memory-corruption patch runs.
 *
 * This header is INTENTIONALLY free of Android/JNI/libc-extras dependencies so
 * that the same logic compiles both inside libexp.so (runtime, aarch64) and in
 * the host unit-test harness (tools/tests/test_target_profile.c) with a plain
 * `cc`. Only <stddef.h>/<stdint.h> and <string.h> are used.
 *
 * Selection order (conceptual):
 *   exact known target
 *     -> exact firmware profile
 *       -> validate firmware/kernel/userspace identity (Gate B, runtime)
 *         -> select profile-specific artifacts where defined
 *           -> otherwise use existing upstream generic behaviour.
 *
 * A firmware that only PARTIALLY matches the ZZIC profile (right model, wrong
 * kernel; right kernel, wrong fingerprint; ...) is classified TARGET_MISMATCH
 * and must NOT be silently accepted as ZZIC.
 */
#ifndef DFR_TARGET_PROFILE_H
#define DFR_TARGET_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------- generic upstream kernel-family module selection (unchanged) -------- */

struct KoImage {
    int android_release;
    int kver_major;
    int kver_minor;
    const char *start;
    const char *end;
};

/*
 * Parse a Linux `uname -r` release string into (android_release, major, minor).
 * Pure string logic, no syscalls, so it is unit-testable off-device. Mirrors
 * the historical upstream read_device_versions() parsing EXACTLY:
 *   - "%d.%d" at the head gives major/minor,
 *   - the integer right after the first "android" token gives android_release.
 * Returns 0 on success, -1 on any parse failure.
 *
 * NOTE (documented upstream behaviour): the ZZIC kernel release
 * "6.6.127-android15-8-...-abogkiS938BXXUCZZIC-4k" parses to
 * android_release=15, major=6, minor=6 -> generic {15,6,6} module. This is
 * kernel-FAMILY selection, NOT proof of identity with the Samsung ZZIC kernel;
 * see classify_target()/gate_b for the identity checks.
 */
int dfr_parse_kernel_versions(const char *release,
                              int *android_release, int *kver_major, int *kver_minor);

/*
 * Upstream generic selection over the compiled-in module table. Identical
 * semantics to the original select_ko_image(): exact (android_release,maj,min)
 * wins; otherwise the first (maj,min) match of any android_release is the
 * fallback; NULL if the kernel major/minor is unknown.
 */
const struct KoImage *dfr_select_ko_image(const struct KoImage *images, size_t n,
                                          int android_release, int kver_major, int kver_minor);

/* -------- exact firmware target/profile (Galaxy S25 Ultra ZZIC) -------- */

/*
 * Everything the profile pins about the exact target. String fields are the
 * canonical values Android/kernel report; hash fields are lowercase hex
 * SHA-256 of the referenced artefact. A NULL/empty hash means "not pinned"
 * (unknown) and Gate B treats it as UNKNOWN rather than PASS/FAIL.
 */
struct TargetProfile {
    const char *id;             /* stable profile id, e.g. "S25U_ZZIC" */
    const char *manufacturer;   /* ro.product.manufacturer */
    const char *model;          /* ro.product.model */
    const char *device;         /* ro.product.device (codename) */
    int         sdk;            /* ro.build.version.sdk */
    int         android_release;/* userspace Android release (17) */
    const char *display;        /* ro.build.display.id */
    const char *fingerprint;    /* ro.build.fingerprint */
    const char *kernel_release; /* uname -r, exact */
    const char *kernel_version; /* uname -v, exact */
    long        page_size;      /* getpagesize() */
    const char *abi;            /* primary ABI, arm64-v8a */
    const char *kernel_arch;    /* uname -m, aarch64 */

    /* pinned artefact hashes (lowercase hex SHA-256) */
    const char *kernel_image_sha256;
    const char *btf_sha256;
    /*
     * First mutation target. On the ZZIC target an unpinned REQUIRED artefact is
     * a FAIL, not an UNKNOWN, so the chain refuses rather than writing to a file
     * whose pristine identity was never established (dossier section 26).
     * Captured from hardware during the v2.0.2-zzic physical run.
     */
    const char *crashdump_sha256;     /* /apex/com.android.runtime/bin/crash_dump64 */
    const char *vendor_target_sha256; /* /vendor/lib64/libstagefrighthw.so */
    const char *libc_sha256;          /* resolved /system/lib64/libc.so target */
    const char *libcxx_sha256;        /* /system/lib64/libc++.so */

    /*
     * Vendor-ELF PROVENANCE anchors (see dfr_vendor_provenance_eval).
     *
     * The v2.0.2-zzic physical run established that /vendor/lib64/libstagefrighthw.so
     * is NOT readable from the domain DFReroot runs in: open(2) returns EACCES
     * from both u:r:system_server:s0 and u:r:network_stack:s0, while the same
     * file hashes fine from u:r:ksu:s0. That is a property of the SELinux policy,
     * not of the file - and the upstream exploit already knows it, which is why
     * patch_ko() writes that target through crash_dump64 (use_helper=1) instead
     * of opening it. Demanding a direct runtime SHA-256 of it was therefore a
     * requirement the architecture itself cannot satisfy.
     *
     * The requirement for PROOF does not go away; the FORM of the proof changes.
     * vendor_target_sha256 was captured on this exact firmware while dm-verity
     * was enforcing, verified boot was green, the bootloader was locked and
     * vbmeta reported the digest below. Under AVB those facts are what make the
     * bytes on /vendor authenticated: same vbmeta digest + enforcing verity +
     * green/locked state means the /vendor tree is bit-identical to the one the
     * digest covers. So the runtime re-establishes THAT chain instead, and any
     * divergence in it is a hard refusal.
     *
     * A NULL/empty anchor is "not pinned" and makes the gate refuse, exactly
     * like an unpinned artefact hash.
     */
    const char *vbmeta_digest;        /* ro.boot.vbmeta.digest */
    const char *vbmeta_avb_version;   /* ro.boot.vbmeta.avb_version */
    const char *vbmeta_hash_alg;      /* ro.boot.vbmeta.hash_alg */
    const char *verified_boot_state;  /* ro.boot.verifiedbootstate, "green" */
    const char *vbmeta_device_state;  /* ro.boot.vbmeta.device_state, "locked" */
    const char *flash_locked;         /* ro.boot.flash.locked, "1" */
    const char *verity_mode;          /* ro.boot.veritymode, "enforcing" */
    const char *vendor_fstype;        /* /vendor filesystem type, "erofs" */
    int         vendor_mount_ro;      /* 1 = /vendor must be mounted read-only */
    /*
     * Observational anchors: both are only checkable when the domain is allowed
     * to stat(2)/getattr the file, which is NOT guaranteed when open(2) is
     * denied. They are compared when available and are a hard FAIL when they
     * are available and diverge; when they are unavailable the gate records
     * SKIP and does not treat the absence as evidence either way. A value of 0 /
     * NULL means the profile pins nothing to compare.
     */
    long        vendor_target_size;   /* st_size of the vendor ELF, 0 = unpinned */
    const char *vendor_target_context;/* its SELinux label, NULL = unpinned */

    /*
     * The ksud that stage2 hands the privileged handoff to. Pinned by bytes for
     * the same reason the module is: the asset is an opaque 6.6 MB binary, and
     * "we shipped a ksud" is not evidence that we shipped THIS one.
     *
     *   ksud_sha256 pinned
     *     IMPLIES ksud_size is pinned
     *     AND SHA-256(the asset bytes actually staged) == ksud_sha256
     *
     * NULL/0 = unpinned, and KsudStage then refuses to stage: an unverified
     * daemon getting uid 0 is exactly the shape of failure this repository
     * exists to prevent. The size is pinned alongside the digest so a truncated
     * read is named as truncation rather than as a digest mismatch.
     */
    const char *ksud_sha256;
    long        ksud_size;

    /* NetworkStack expectations */
    const char *network_stack_process;
    int         network_stack_uid;
    const char *network_stack_context;
    long        network_stack_cap_eff; /* CapEff bitmask, e.g. 0x800003c00 */

    /*
     * Whether a kernel module positively validated for THIS firmware is bundled
     * (Gate G COMPATIBLE against the ZZIC Module.symvers). 0 = only the generic
     * android15-6.6 module is available and it is Gate-G UNVERIFIED, so loading
     * it on ZZIC is fail-closed-refused unless the operator opts in explicitly.
     *
     * A bare boolean is not evidence. The invariant the runtime enforces is:
     *
     *   ko_zzic_verified == 1
     *     IMPLIES ko_sha256 is pinned
     *     AND SHA-256(bundled module bytes actually selected) == ko_sha256
     *
     * so flipping the flag without pinning the digest of the exact validated
     * module, or bundling different bytes than the ones that were validated,
     * refuses at run time instead of silently loading an unvalidated module.
     * tools/profile_binding_audit.py enforces the same invariant in CI.
     */
    int         ko_zzic_verified;
    const char *ko_filename;  /* validated module's filename, or NULL */
    const char *ko_sha256;    /* its lowercase hex SHA-256, or NULL */
};

extern const struct TargetProfile DFR_PROFILE_ZZIC;

typedef enum {
    DFR_TARGET_UPSTREAM_GENERIC = 0, /* unrelated device: run upstream path */
    DFR_TARGET_S25U_ZZIC        = 1, /* exact ZZIC target */
    DFR_TARGET_MISMATCH         = 2  /* looks like the ZZIC target but deviates */
} dfr_target_class;

/* -------- Gate G: chain-level module policy (pure, host-testable) -------- */

/*
 * Verdict of the Gate-G policy for one page-cache corruption stage.
 *
 * DFR_MODULE_POLICY_ALLOW means only that the profile's three ko_* fields are
 * present together. It is NOT the byte binding: SHA-256(selected module bytes)
 * == ko_sha256 is deliberately not evaluated here, because only the stage that
 * actually selects the payload holds those bytes. That check stays in patch_ko(),
 * where it can be proven rather than assumed.
 */
typedef enum {
    DFR_MODULE_POLICY_NOT_APPLICABLE     = 0, /* not the exact ZZIC target */
    DFR_MODULE_POLICY_ALLOW              = 1, /* all three ko_* fields present */
    DFR_MODULE_POLICY_REFUSE_UNVERIFIED  = 2, /* ko_zzic_verified = 0 */
    DFR_MODULE_POLICY_REFUSE_NO_DIGEST   = 3, /* flag set, ko_sha256 unpinned */
    DFR_MODULE_POLICY_REFUSE_NO_FILENAME = 4  /* flag set, ko_filename unset */
} dfr_module_policy;

/*
 * Fail-closed Gate-G policy for the exact ZZIC target.
 *
 * EVERY page-cache corruption stage consults this, not only the stage that
 * writes the module. On ZZIC the earlier writes (crash_dump64, the vendor file,
 * libc, libc++) exist for one purpose: to make the kernel load the module. If
 * the load can never be permitted, corrupting those files is risk with no
 * reachable outcome, so the whole chain refuses at its first stage instead of
 * refusing only at the last one.
 *
 * A bare boolean is not evidence: ko_zzic_verified=1 grants nothing unless
 * ko_sha256 and ko_filename are pinned alongside it (the header invariant above,
 * dossier section 39). `p` may be NULL only when `cls` is not the ZZIC target.
 */
dfr_module_policy dfr_module_policy_eval(dfr_target_class cls,
                                         const struct TargetProfile *p);

/* Stable log token for a verdict, e.g. "REFUSE_UNVERIFIED". Never NULL. */
const char *dfr_module_policy_name(dfr_module_policy v);

/* 1 if the verdict permits the stage to proceed, 0 if it must refuse. */
int dfr_module_policy_permits(dfr_module_policy v);

/* -------- Gate B: vendor-ELF provenance (pure, host-testable) -------- */

/*
 * What the runtime can actually observe about the vendor ELF and the AVB state
 * it sits under. Every string is the raw value as read from a system property
 * or /proc; NULL means "the runtime could not read it at all", which is never
 * treated as agreement.
 */
/*
 * EACCES as a plain constant. This header stays free of <errno.h> so the host
 * test harness compiles it unchanged; exp.c asserts at compile time that the
 * platform's EACCES really is this value, so the two can never drift.
 */
#define DFR_EACCES 13

struct VendorObservation {
    /* ro.boot.* as reported by the bootloader, readable from any domain. */
    const char *verified_boot_state;
    const char *vbmeta_device_state;
    const char *flash_locked;
    const char *verity_mode;
    const char *vbmeta_digest;
    const char *vbmeta_avb_version;
    const char *vbmeta_hash_alg;

    /* /vendor mount, parsed from /proc/self/mountinfo. */
    const char *vendor_fstype;
    int         vendor_ro;      /* 1 = ro, 0 = rw, -1 = could not determine */

    /*
     * Direct read of the vendor ELF. `direct_sha256` is the lowercase hex
     * digest when the open+read succeeded, NULL when it did not; in that case
     * `direct_errno` carries the errno. EACCES is the one documented, expected
     * denial on this firmware; anything else is a fault, not a policy.
     */
    const char *direct_sha256;
    int         direct_errno;

    /* Observational, -1 / NULL when getattr was denied or failed. */
    long        size;
    const char *context;
};

typedef enum {
    DFR_VENDOR_PROV_NOT_APPLICABLE       = 0, /* not the exact ZZIC target */
    DFR_VENDOR_PROV_PASS_DIRECT          = 1, /* direct SHA-256 matched, chain intact */
    DFR_VENDOR_PROV_PASS_AVB             = 2, /* direct denied (EACCES), chain intact */
    DFR_VENDOR_PROV_FAIL_NO_PIN          = 3, /* the profile pins no provenance */
    DFR_VENDOR_PROV_FAIL_DIRECT_MISMATCH = 4, /* readable and NOT the pinned bytes */
    DFR_VENDOR_PROV_FAIL_UNREADABLE      = 5, /* unreadable for a reason other than EACCES */
    DFR_VENDOR_PROV_FAIL_CHAIN           = 6  /* an AVB / mount element diverged or is absent */
} dfr_vendor_prov;

/* Per-element breakdown, so a refusal names the element that broke. */
struct VendorProvMatch {
    dfr_vendor_prov verdict;
    int verified_boot_state_ok;
    int vbmeta_device_state_ok;
    int flash_locked_ok;
    int verity_mode_ok;
    int vbmeta_digest_ok;
    int vbmeta_avb_version_ok;
    int vbmeta_hash_alg_ok;
    int vendor_fstype_ok;
    int vendor_ro_ok;
    int chain_ok;        /* every element above matched */
    int direct_available; /* 1 if the runtime got a digest out of the file */
    int direct_ok;        /* 1 if that digest equals vendor_target_sha256 */
    int size_checked;     /* 1 if both profile and observation had a size */
    int size_ok;
    int context_checked;
    int context_ok;
};

/*
 * Fail-closed vendor-ELF provenance decision for the exact ZZIC target.
 *
 * Rules, in order:
 *   1. Not the ZZIC target                       -> NOT_APPLICABLE.
 *   2. Missing profile/observation, or any
 *      provenance anchor left unpinned           -> FAIL_NO_PIN (refuse).
 *   3. The file WAS readable and its digest is
 *      not the pinned one                        -> FAIL_DIRECT_MISMATCH.
 *   4. Any AVB/mount element absent or divergent,
 *      or an available size/label that diverges  -> FAIL_CHAIN.
 *   5. The file was unreadable for any errno
 *      other than EACCES                         -> FAIL_UNREADABLE.
 *   6. Otherwise PASS_DIRECT (digest matched) or
 *      PASS_AVB (EACCES, chain intact).
 *
 * Note what is NOT here: there is no verdict that turns EACCES into a pass on
 * its own. EACCES only ever relaxes WHICH proof is required, never WHETHER one
 * is required, and the replacement proof is strictly the AVB chain the pinned
 * digest was captured under.
 */
dfr_vendor_prov dfr_vendor_provenance_eval(dfr_target_class cls,
                                           const struct TargetProfile *p,
                                           const struct VendorObservation *o,
                                           struct VendorProvMatch *out);

/* Stable log token for a verdict, e.g. "PASS_AVB". Never NULL. */
const char *dfr_vendor_prov_name(dfr_vendor_prov v);

/* 1 if the verdict permits the stage to proceed, 0 if it must refuse. */
int dfr_vendor_prov_permits(dfr_vendor_prov v);

/*
 * Parse /proc/self/mountinfo content and report how `mountpoint` is mounted.
 * The LAST matching line wins, which is what the kernel means by the effective
 * mount. `*fstype` receives a pointer into a caller-provided buffer.
 * Returns 1 when the mountpoint was found, 0 when it was not.
 */
int dfr_mountinfo_lookup(const char *mountinfo, const char *mountpoint,
                         char *fstype_out, size_t fstype_len, int *ro_out);

/* Observed device identity, filled from Android props + uname (or test vectors). */
struct ObservedTarget {
    const char *manufacturer;
    const char *model;
    const char *device;
    int         sdk;
    int         android_release; /* ro.build.version.release as int (17) */
    const char *display;
    const char *fingerprint;
    const char *kernel_release;
    const char *kernel_version; /* uname -v */
    const char *kernel_arch;    /* uname -m */
    long        page_size;
    const char *abi;
};

/* Per-field match result, for Gate A diagnostics (1=match, 0=mismatch). */
struct TargetMatch {
    dfr_target_class cls;
    int manufacturer_ok;
    int model_ok;
    int device_ok;
    int sdk_ok;
    int android_release_ok;
    int display_ok;
    int fingerprint_ok;
    int kernel_release_ok;
    int kernel_version_ok;
    int kernel_arch_ok;
    int page_size_ok;
    int abi_ok;
    int anchor_hit;   /* set if this device asserts the ZZIC model/codename */
    int all_ok;       /* set iff every field above matched */
};

/*
 * Fail-closed classification against DFR_PROFILE_ZZIC.
 *  - all identity fields match           -> DFR_TARGET_S25U_ZZIC
 *  - ZZIC model/codename present but any
 *    field deviates                      -> DFR_TARGET_MISMATCH  (refuse)
 *  - no ZZIC anchor at all               -> DFR_TARGET_UPSTREAM_GENERIC
 * `out` (may be NULL) receives the per-field breakdown for logging.
 */
dfr_target_class dfr_classify_target(const struct ObservedTarget *obs,
                                     struct TargetMatch *out);

/* Case-sensitive equality that treats NULL as "no value" (never matches). */
int dfr_streq(const char *a, const char *b);

#ifdef __cplusplus
}
#endif

#endif /* DFR_TARGET_PROFILE_H */
