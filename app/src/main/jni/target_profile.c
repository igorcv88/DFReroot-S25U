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
    /* Captured from the ZZIC device itself during the v2.0.2-zzic physical run
     * (dossier section 26 is closed). crash_dump64 IS readable from the domain
     * the chain runs in, so this one stays a direct runtime SHA-256 check. */
    .crashdump_sha256 =
        "9249d66445837c52322c2c86ee62efa64e49a7c1b72084c1ce98f72c12a1151f",
    .vendor_target_sha256 =
        "308b254a82c51695015182fc3b78b5d0cbb6e36cd6cf8f2f282452f8a47f8049",
    .libc_sha256 =
        "88fba68b3d1fded4bfd25197f6de24f5b8794d3253de860ee261a4272be9e861",
    .libcxx_sha256 =
        "cb118e98c74d3454858921123b9b51ba13df9cad7dfa141dd892c453661a4d78",

    /* Vendor-ELF provenance anchors, all observed on the ZZIC device in the
     * same boot the vendor_target_sha256 above was captured in. */
    .vbmeta_digest =
        "23a0e0b0a5b421d5a75b62de40edb37489a4e6d441d54e58ee6f930c1a9a3f62",
    .vbmeta_avb_version   = "1.2",
    .vbmeta_hash_alg      = "sha256",
    .verified_boot_state  = "green",
    .vbmeta_device_state  = "locked",
    .flash_locked         = "1",
    .verity_mode          = "enforcing",
    .vendor_fstype        = "erofs",
    .vendor_mount_ro      = 1,
    .vendor_target_size   = 51632,
    .vendor_target_context = "u:object_r:vendor_file:s0",

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

dfr_module_policy dfr_module_policy_eval(dfr_target_class cls,
                                         const struct TargetProfile *p) {
    if (cls != DFR_TARGET_S25U_ZZIC)
        return DFR_MODULE_POLICY_NOT_APPLICABLE;
    /* A ZZIC classification with no profile to consult cannot be evaluated, and
     * "cannot evaluate" is a refusal, never a pass. */
    if (p == NULL)
        return DFR_MODULE_POLICY_REFUSE_UNVERIFIED;
    if (!p->ko_zzic_verified)
        return DFR_MODULE_POLICY_REFUSE_UNVERIFIED;
    if (p->ko_sha256 == NULL || p->ko_sha256[0] == 0)
        return DFR_MODULE_POLICY_REFUSE_NO_DIGEST;
    if (p->ko_filename == NULL || p->ko_filename[0] == 0)
        return DFR_MODULE_POLICY_REFUSE_NO_FILENAME;
    return DFR_MODULE_POLICY_ALLOW;
}

const char *dfr_module_policy_name(dfr_module_policy v) {
    switch (v) {
        case DFR_MODULE_POLICY_NOT_APPLICABLE:     return "NOT_APPLICABLE";
        case DFR_MODULE_POLICY_ALLOW:              return "ALLOW";
        case DFR_MODULE_POLICY_REFUSE_UNVERIFIED:  return "REFUSE_UNVERIFIED";
        case DFR_MODULE_POLICY_REFUSE_NO_DIGEST:   return "REFUSE_NO_DIGEST";
        case DFR_MODULE_POLICY_REFUSE_NO_FILENAME: return "REFUSE_NO_FILENAME";
    }
    /* An unnamed verdict is not a known-good one; report it as such. */
    return "REFUSE_UNKNOWN_VERDICT";
}

int dfr_module_policy_permits(dfr_module_policy v) {
    return v == DFR_MODULE_POLICY_NOT_APPLICABLE || v == DFR_MODULE_POLICY_ALLOW;
}

/* -------- Gate B: vendor-ELF provenance -------- */

/* A pinned anchor is a non-NULL, non-empty string. */
static int pinned(const char *v) { return v != NULL && v[0] != 0; }

int dfr_mountinfo_lookup(const char *mountinfo, const char *mountpoint,
                         char *fstype_out, size_t fstype_len, int *ro_out) {
    const char *line = mountinfo;
    int found = 0;
    if (fstype_out && fstype_len) fstype_out[0] = 0;
    if (ro_out) *ro_out = -1;
    if (mountinfo == NULL || mountpoint == NULL) return 0;

    while (*line) {
        const char *eol = strchr(line, '\n');
        size_t linelen = eol ? (size_t)(eol - line) : strlen(line);
        /*
         * mountinfo: id parent major:minor root MOUNTPOINT OPTIONS ... - FSTYPE
         * source super-options. Fields are space-separated; the optional fields
         * between OPTIONS and the "-" separator are what make a fixed index
         * wrong, so the separator is located explicitly.
         */
        const char *f = line;
        const char *end = line + linelen;
        const char *mp = NULL, *opts = NULL;
        int idx = 0;
        while (f < end) {
            const char *sp = f;
            while (sp < end && *sp != ' ') sp++;
            if (idx == 4) mp = f;
            if (idx == 5) opts = f;
            idx++;
            f = (sp < end) ? sp + 1 : end;
            if (idx > 5 && mp && opts) break;
        }
        if (mp && opts) {
            size_t mplen = 0;
            while (mp + mplen < end && mp[mplen] != ' ') mplen++;
            if (mplen == strlen(mountpoint) && strncmp(mp, mountpoint, mplen) == 0) {
                /* find " - " separator, then the fstype right after it */
                const char *sep = mp;
                const char *fstype = NULL;
                while (sep + 2 < end) {
                    if (sep[0] == ' ' && sep[1] == '-' && sep[2] == ' ') {
                        fstype = sep + 3;
                        break;
                    }
                    sep++;
                }
                if (fstype) {
                    size_t n = 0;
                    while (fstype + n < end && fstype[n] != ' ') n++;
                    if (fstype_out && fstype_len) {
                        size_t copy = n < fstype_len - 1 ? n : fstype_len - 1;
                        memcpy(fstype_out, fstype, copy);
                        fstype_out[copy] = 0;
                    }
                }
                if (ro_out) {
                    /* the per-mount options field: "ro,..." or "rw,..." */
                    if (end - opts >= 2 && opts[0] == 'r' && opts[1] == 'o' &&
                        (end - opts == 2 || opts[2] == ',' || opts[2] == ' '))
                        *ro_out = 1;
                    else if (end - opts >= 2 && opts[0] == 'r' && opts[1] == 'w' &&
                             (end - opts == 2 || opts[2] == ',' || opts[2] == ' '))
                        *ro_out = 0;
                    else
                        *ro_out = -1;
                }
                found = 1; /* keep going: the LAST match is the effective mount */
            }
        }
        if (!eol) break;
        line = eol + 1;
    }
    return found;
}

dfr_vendor_prov dfr_vendor_provenance_eval(dfr_target_class cls,
                                           const struct TargetProfile *p,
                                           const struct VendorObservation *o,
                                           struct VendorProvMatch *out) {
    struct VendorProvMatch m;
    memset(&m, 0, sizeof(m));
    m.verdict = DFR_VENDOR_PROV_FAIL_NO_PIN;

    if (cls != DFR_TARGET_S25U_ZZIC) {
        m.verdict = DFR_VENDOR_PROV_NOT_APPLICABLE;
        if (out) *out = m;
        return m.verdict;
    }
    /* Nothing to compare against is a refusal, never a pass. */
    if (p == NULL || o == NULL) {
        if (out) *out = m;
        return m.verdict;
    }
    /*
     * Every anchor must be pinned BEFORE anything is compared. A half-pinned
     * profile would otherwise "pass" the elements it happens to declare and
     * silently skip the rest - which is precisely the shape of proof this gate
     * exists to reject.
     */
    if (!pinned(p->vendor_target_sha256) ||
        !pinned(p->vbmeta_digest) ||
        !pinned(p->vbmeta_avb_version) ||
        !pinned(p->vbmeta_hash_alg) ||
        !pinned(p->verified_boot_state) ||
        !pinned(p->vbmeta_device_state) ||
        !pinned(p->flash_locked) ||
        !pinned(p->verity_mode) ||
        !pinned(p->vendor_fstype) ||
        p->vendor_mount_ro < 0) {
        if (out) *out = m;
        return m.verdict;
    }

    m.verified_boot_state_ok = dfr_streq(o->verified_boot_state, p->verified_boot_state);
    m.vbmeta_device_state_ok = dfr_streq(o->vbmeta_device_state, p->vbmeta_device_state);
    m.flash_locked_ok        = dfr_streq(o->flash_locked, p->flash_locked);
    m.verity_mode_ok         = dfr_streq(o->verity_mode, p->verity_mode);
    m.vbmeta_digest_ok       = dfr_streq(o->vbmeta_digest, p->vbmeta_digest);
    m.vbmeta_avb_version_ok  = dfr_streq(o->vbmeta_avb_version, p->vbmeta_avb_version);
    m.vbmeta_hash_alg_ok     = dfr_streq(o->vbmeta_hash_alg, p->vbmeta_hash_alg);
    m.vendor_fstype_ok       = dfr_streq(o->vendor_fstype, p->vendor_fstype);
    m.vendor_ro_ok           = (o->vendor_ro == p->vendor_mount_ro);

    /*
     * Observational anchors. Unavailable (size < 0 / context NULL) is recorded
     * as "not checked" rather than as agreement; available-and-divergent is a
     * hard failure, because a vendor file of a different size or label than the
     * one the digest was captured from is not the pinned artefact.
     */
    m.size_checked = (p->vendor_target_size > 0 && o->size >= 0);
    m.size_ok = !m.size_checked || (o->size == p->vendor_target_size);
    m.context_checked = (pinned(p->vendor_target_context) && o->context != NULL);
    m.context_ok = !m.context_checked || dfr_streq(o->context, p->vendor_target_context);

    m.chain_ok = m.verified_boot_state_ok && m.vbmeta_device_state_ok &&
                 m.flash_locked_ok && m.verity_mode_ok && m.vbmeta_digest_ok &&
                 m.vbmeta_avb_version_ok && m.vbmeta_hash_alg_ok &&
                 m.vendor_fstype_ok && m.vendor_ro_ok &&
                 m.size_ok && m.context_ok;

    m.direct_available = pinned(o->direct_sha256);
    m.direct_ok = m.direct_available &&
                  dfr_streq(o->direct_sha256, p->vendor_target_sha256);

    if (m.direct_available && !m.direct_ok)
        m.verdict = DFR_VENDOR_PROV_FAIL_DIRECT_MISMATCH;
    else if (!m.chain_ok)
        m.verdict = DFR_VENDOR_PROV_FAIL_CHAIN;
    else if (m.direct_available)
        m.verdict = DFR_VENDOR_PROV_PASS_DIRECT;
    else if (o->direct_errno == DFR_EACCES)
        m.verdict = DFR_VENDOR_PROV_PASS_AVB;
    else
        m.verdict = DFR_VENDOR_PROV_FAIL_UNREADABLE;

    if (out) *out = m;
    return m.verdict;
}

const char *dfr_vendor_prov_name(dfr_vendor_prov v) {
    switch (v) {
        case DFR_VENDOR_PROV_NOT_APPLICABLE:       return "NOT_APPLICABLE";
        case DFR_VENDOR_PROV_PASS_DIRECT:          return "PASS_DIRECT";
        case DFR_VENDOR_PROV_PASS_AVB:             return "PASS_AVB";
        case DFR_VENDOR_PROV_FAIL_NO_PIN:          return "FAIL_NO_PIN";
        case DFR_VENDOR_PROV_FAIL_DIRECT_MISMATCH: return "FAIL_DIRECT_MISMATCH";
        case DFR_VENDOR_PROV_FAIL_UNREADABLE:      return "FAIL_UNREADABLE";
        case DFR_VENDOR_PROV_FAIL_CHAIN:           return "FAIL_CHAIN";
    }
    /* An unnamed verdict is not a known-good one; report it as such. */
    return "FAIL_UNKNOWN_VERDICT";
}

int dfr_vendor_prov_permits(dfr_vendor_prov v) {
    return v == DFR_VENDOR_PROV_NOT_APPLICABLE ||
           v == DFR_VENDOR_PROV_PASS_DIRECT ||
           v == DFR_VENDOR_PROV_PASS_AVB;
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
