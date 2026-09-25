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
    const char *crashdump_sha256;     /* /apex/com.android.runtime/bin/crash_dump64 */
    const char *vendor_target_sha256; /* /vendor/lib64/libstagefrighthw.so */
    const char *libc_sha256;          /* resolved /system/lib64/libc.so target */
    const char *libcxx_sha256;        /* /system/lib64/libc++.so */

    /* NetworkStack expectations */
    const char *network_stack_process;
    int         network_stack_uid;
    const char *network_stack_context;
    long        network_stack_cap_eff; /* CapEff bitmask, e.g. 0x800003c00 */

    /*
     * Whether a kernel module positively validated for THIS firmware is bundled
     * (Gate G COMPATIBLE against the ZZIC Module.symvers). 0 = only the generic
     * android15-6.6 module is available and it is Gate-G UNVERIFIED, so every
     * mutating ZZIC entry point remains fail-closed until a validated module is
     * explicitly bundled and this flag is changed as part of that reviewed port.
     */
    int         ko_zzic_verified;
};

extern const struct TargetProfile DFR_PROFILE_ZZIC;

typedef enum {
    DFR_TARGET_UPSTREAM_GENERIC = 0, /* unrelated device: run upstream path */
    DFR_TARGET_S25U_ZZIC        = 1, /* exact ZZIC target */
    DFR_TARGET_MISMATCH         = 2  /* looks like the ZZIC target but deviates */
} dfr_target_class;

/* Observed device identity, filled from Android props + uname (or test vectors). */
struct ObservedTarget {
    const char *manufacturer;
    const char *model;
    const char *device;
    int         sdk;
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
