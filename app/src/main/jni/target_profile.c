/*
 * target_profile.c - see target_profile.h.
 *
 * No Android/JNI/syscall dependencies: pure data + string logic so the exact
 * same object is exercised by the host unit tests.
 */
#include "target_profile.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * The one exact firmware this profile recognises. Values are the canonical
 * target identity for Galaxy S25 Ultra SM-S938B / One UI 9 Beta 3 running
 * S938BXXUCZZIC. Hashes are the artefacts pinned by the compatibility work.
 */
const struct TargetProfile DFR_PROFILE_ZZIC = {
    .id            = "S25U_ZZIC",
    /* ro.product.manufacturer is lowercase on Samsung firmware ("samsung",
     * as the fingerprint prefix also shows). Comparison is case-sensitive,
     * so the exact observed casing is mandatory here: "Samsung" would make
     * the real target classify as MISMATCH and refuse everything. */
    .manufacturer  = "samsung",
    .model         = "SM-S938B",
    .device        = "pa3q",
    .sdk           = 37,
    .android_release = 17,
    .display       = "CP2A.260605.016.S938BXXUCZZIC",
    .fingerprint   = "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/"
                     "S938BXXUCZZIC_OXMCZZIC:user/release-keys",
    .kernel_release = "6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k",
    .kernel_version = "#1 SMP PREEMPT Wed Sep 16 14:21:43 UTC 2026",
    .page_size      = 4096,
    .abi            = "arm64-v8a",
    .kernel_arch    = "aarch64",

    .kernel_image_sha256 =
        "470d40df59320e01b1449f8dbe962e0d44d735c817b99293dc6da286175ffcf3",
    .btf_sha256 =
        "e13df32a16b5536c43897542b4dbc2c7082f2aefb91249bc94a06bfc5870950c",
    /* Unknown: dossier section 26, the immediate Gate B blocker. Keep NULL so
     * the ZZIC path refuses instead of patching an unvalidated crash_dump64. */
    .crashdump_sha256 = NULL,
    .vendor_target_sha256 =
        "308b254a82c51695015182fc3b78b5d0cbb6e36cd6cf8f2f282452f8a47f8049",
    .libc_sha256 =
        "88fba68b3d1fded4bfd25197f6de24f5b8794d3253de860ee261a4272be9e861",
    .libcxx_sha256 =
        "cb118e98c74d3454858921123b9b51ba13df9cad7dfa141dd892c453661a4d78",

    .network_stack_process = "com.android.networkstack.process",
    .network_stack_uid     = 1073,
    .network_stack_context = "u:r:network_stack:s0",
    .network_stack_cap_eff = 0x800003c00L,

    /* No ZZIC-validated module is bundled: only the generic Gate-G UNVERIFIED
     * android15-6.6 .ko exists. Keep fail-closed until one is proven. When one
     * is, set all three fields together (see the header's invariant): the flag
     * alone grants nothing without the pinned digest of the exact bytes. */
    .ko_zzic_verified = 0,
    .ko_filename      = NULL,
    .ko_sha256        = NULL,
};

int dfr_streq(const char *a, const char *b) {
    if (a == NULL || b == NULL) return 0;
    return strcmp(a, b) == 0;
}

int dfr_parse_kernel_versions(const char *release,
                              int *android_release, int *kver_major, int *kver_minor) {
    const char *marker;
    if (release == NULL) return -1;
    if (sscanf(release, "%d.%d", kver_major, kver_minor) != 2)
        return -1;
    marker = strstr(release, "android");
    if (marker == NULL) return -1;
    *android_release = atoi(marker + 7);
    if (*android_release <= 0) return -1;
    return 0;
}

const struct KoImage *dfr_select_ko_image(const struct KoImage *images, size_t n,
                                          int android_release, int kver_major, int kver_minor) {
    const struct KoImage *fallback = NULL;
    size_t i;
    for (i = 0; i < n; i++) {
        if (images[i].kver_major != kver_major || images[i].kver_minor != kver_minor)
            continue;
        if (images[i].android_release == android_release)
            return &images[i];
        if (fallback == NULL)
            fallback = &images[i];
    }
    return fallback;
}

dfr_target_class dfr_classify_target(const struct ObservedTarget *obs,
                                     struct TargetMatch *out) {
    const struct TargetProfile *p = &DFR_PROFILE_ZZIC;
    struct TargetMatch m;
    memset(&m, 0, sizeof(m));

    if (obs == NULL) {
        if (out) *out = m;
        return DFR_TARGET_UPSTREAM_GENERIC;
    }

    m.manufacturer_ok   = dfr_streq(obs->manufacturer, p->manufacturer);
    m.model_ok          = dfr_streq(obs->model, p->model);
    m.device_ok         = dfr_streq(obs->device, p->device);
    m.sdk_ok            = (obs->sdk == p->sdk);
    /*
     * android_release is compared, not merely stored: an SDK number can be
     * shared by a platform release and its beta, so leaving the pinned value
     * unenforced would mean the profile advertises a field it never checks.
     */
    m.android_release_ok = (obs->android_release == p->android_release);
    m.display_ok        = dfr_streq(obs->display, p->display);
    m.fingerprint_ok    = dfr_streq(obs->fingerprint, p->fingerprint);
    m.kernel_release_ok = dfr_streq(obs->kernel_release, p->kernel_release);
    m.kernel_version_ok = dfr_streq(obs->kernel_version, p->kernel_version);
    m.kernel_arch_ok    = dfr_streq(obs->kernel_arch, p->kernel_arch);
    m.page_size_ok      = (obs->page_size == p->page_size);
    m.abi_ok            = dfr_streq(obs->abi, p->abi);

    m.all_ok = m.manufacturer_ok && m.model_ok && m.device_ok && m.sdk_ok &&
               m.android_release_ok &&
               m.display_ok && m.fingerprint_ok && m.kernel_release_ok &&
               m.kernel_version_ok && m.kernel_arch_ok &&
               m.page_size_ok && m.abi_ok;

    /*
     * Identity anchors: the model and codename are unique to THIS device.
     * If either asserts SM-S938B/pa3q the device is claiming to be the ZZIC
     * target, so anything short of a full exact match is a hard mismatch
     * (fail-closed) rather than a silent fall-through to the generic path.
     */
    m.anchor_hit = m.model_ok || m.device_ok;

    if (m.all_ok)        m.cls = DFR_TARGET_S25U_ZZIC;
    else if (m.anchor_hit) m.cls = DFR_TARGET_MISMATCH;
    else                 m.cls = DFR_TARGET_UPSTREAM_GENERIC;

    if (out) *out = m;
    return m.cls;
}
