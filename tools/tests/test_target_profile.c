/*
 * test_target_profile.c - host unit + regression tests for DFReroot's target
 * profile logic. Compiles and runs with a plain cc on any host (no Android):
 *
 *   cc -I app/src/main/jni -o test_tp \
 *      tools/tests/test_target_profile.c \
 *      app/src/main/jni/target_profile.c app/src/main/jni/sha256.c && ./test_tp
 *
 * See tools/tests/run_tests.sh.
 *
 * Coverage:
 *   [A] Target detection: exact ZZIC PASS + every required negative case FAIL.
 *   [R] Regression: upstream generic kernel-family selection unchanged for the
 *       full upstream module table.
 *   [S] SHA-256 known-answer, guards the Gate B/F hashing primitive.
 */
#include "target_profile.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
static int g_total = 0;

#define CHECK(cond, ...) do { \
    g_total++; \
    if (cond) { printf("  ok   - "); } \
    else { g_fail++; printf("  FAIL - "); } \
    printf(__VA_ARGS__); printf("\n"); \
} while (0)

/* ---- canonical ZZIC observed identity (matches the profile exactly) ---- */
static struct ObservedTarget zzic_observed(void) {
    struct ObservedTarget o;
    memset(&o, 0, sizeof(o));
    o.manufacturer  = "samsung";  /* lowercase: the value the device reports */
    o.model         = "SM-S938B";
    o.device        = "pa3q";
    o.sdk           = 37;
    o.android_release = 17;
    o.display       = "CP2A.260605.016.S938BXXUCZZIC";
    o.fingerprint   = "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/"
                      "S938BXXUCZZIC_OXMCZZIC:user/release-keys";
    o.kernel_release = "6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k";
    o.kernel_version = "#1 SMP PREEMPT Wed Sep 16 14:21:43 UTC 2026";
    o.kernel_arch   = "aarch64";
    o.page_size     = 4096;
    o.abi           = "arm64-v8a";
    return o;
}

static const char *cls_name(dfr_target_class c) {
    switch (c) {
        case DFR_TARGET_S25U_ZZIC: return "S25U_ZZIC";
        case DFR_TARGET_MISMATCH:  return "MISMATCH";
        default:                   return "UPSTREAM_GENERIC";
    }
}

static void test_target_detection(void) {
    printf("[A] target detection\n");
    struct TargetMatch m;

    /* exact ZZIC -> S25U_ZZIC */
    struct ObservedTarget o = zzic_observed();
    dfr_target_class c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_S25U_ZZIC, "exact ZZIC -> %s (all_ok=%d)", cls_name(c), m.all_ok);

    /* SM-S938B + ZZI4 firmware: right model, ZZI4 display/fingerprint/kernel */
    o = zzic_observed();
    o.display = "CP2A.260605.016.S938BXXUCZZI4";
    o.fingerprint = "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/"
                    "S938BXXUCZZI4_OXMCZZI4:user/release-keys";
    o.kernel_release = "6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZI4-4k";
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH, "SM-S938B + ZZI4 -> %s (must be MISMATCH)", cls_name(c));

    /* SM-S938U (US variant) -> not ZZIC */
    o = zzic_observed();
    o.model = "SM-S938U";
    o.device = "pa3qks";
    o.fingerprint = "samsung/pa3qksx/pa3qks:17/CP2A.260605.016/"
                    "S938U...:user/release-keys";
    c = dfr_classify_target(&o, &m);
    CHECK(c != DFR_TARGET_S25U_ZZIC, "SM-S938U -> %s (must NOT be ZZIC)", cls_name(c));

    /* SM-S938N (Korea variant) -> not ZZIC */
    o = zzic_observed();
    o.model = "SM-S938N";
    o.device = "pa3qks";
    c = dfr_classify_target(&o, &m);
    CHECK(c != DFR_TARGET_S25U_ZZIC, "SM-S938N -> %s (must NOT be ZZIC)", cls_name(c));

    /* pa3q + other display -> MISMATCH (codename anchor present) */
    o = zzic_observed();
    o.display = "CP2A.260605.099.SOMETHINGELSE";
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH, "pa3q + other display -> %s (must be MISMATCH)", cls_name(c));

    /* ZZIC display but a different kernel -> MISMATCH (model anchor present) */
    o = zzic_observed();
    o.kernel_release = "6.6.30-android15-4-something-else-4k";
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH, "ZZIC display + different kernel -> %s (must be MISMATCH)", cls_name(c));

    /* same kernel, different fingerprint -> MISMATCH (model anchor present) */
    o = zzic_observed();
    o.fingerprint = "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/OTHER:user/release-keys";
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH, "same kernel + different fingerprint -> %s (must be MISMATCH)", cls_name(c));

    /* same kernel_release but a rebuilt kernel (different uname -v) -> MISMATCH */
    o = zzic_observed();
    o.kernel_version = "#2 SMP PREEMPT Fri Oct 10 00:00:00 UTC 2026";
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH, "same kernel_release + different kernel_version -> %s (must be MISMATCH)", cls_name(c));

    /* different kernel arch -> MISMATCH (model anchor present) */
    o = zzic_observed();
    o.kernel_arch = "armv8l";
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH, "different kernel_arch -> %s (must be MISMATCH)", cls_name(c));

    /*
     * Property casing is part of the identity. `ro.product.manufacturer` is
     * lowercase "samsung" on this firmware, so the profile must pin exactly
     * that: a capitalised "Samsung" in the profile would turn the real device
     * into a MISMATCH and refuse the whole chain. Assert both directions.
     */
    CHECK(strcmp(DFR_PROFILE_ZZIC.manufacturer, "samsung") == 0,
          "profile pins lowercase manufacturer (got \"%s\")", DFR_PROFILE_ZZIC.manufacturer);
    o = zzic_observed();
    o.manufacturer = "Samsung";
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH && !m.manufacturer_ok,
          "capitalised manufacturer -> %s (case-sensitive compare)", cls_name(c));

    /* android_release is pinned AND enforced (dossier section 57). */
    o = zzic_observed();
    o.android_release = 16;
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH && !m.android_release_ok,
          "android_release 16 on ZZIC hardware -> %s (must be MISMATCH)", cls_name(c));
    o = zzic_observed();
    o.android_release = 0; /* ro.build.version.release unreadable */
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_MISMATCH,
          "missing android_release -> %s (fail-closed, never assumed)", cls_name(c));

    /* unrelated Samsung 6.6 device -> UPSTREAM_GENERIC (upstream path preserved) */
    o = zzic_observed();
    o.model = "SM-S931B"; o.device = "s25"; o.sdk = 35; o.android_release = 15;
    o.display = "AP3A.240905.015.A1"; o.fingerprint = "samsung/s25.../...";
    o.kernel_release = "6.6.30-android15-4-gki-4k";
    c = dfr_classify_target(&o, &m);
    CHECK(c == DFR_TARGET_UPSTREAM_GENERIC, "other Samsung 6.6 -> %s (must be UPSTREAM_GENERIC)", cls_name(c));
}

/* Mirror of the real compiled-in module table (data only; no .ko bytes). */
static const struct KoImage UPSTREAM_TABLE[] = {
    {12, 5, 10, 0, 0}, {13, 5, 10, 0, 0}, {13, 5, 15, 0, 0}, {14, 5, 15, 0, 0},
    {14, 6, 1, 0, 0},  {15, 6, 6, 0, 0},  {16, 6, 12, 0, 0}, {17, 6, 18, 0, 0},
};
#define TABLE_N (sizeof(UPSTREAM_TABLE)/sizeof(UPSTREAM_TABLE[0]))

static void expect_select(int rel, int maj, int min, int erel) {
    const struct KoImage *k = dfr_select_ko_image(UPSTREAM_TABLE, TABLE_N, rel, maj, min);
    if (!k) { g_total++; g_fail++; printf("  FAIL - select(%d,%d.%d) -> NULL\n", rel, maj, min); return; }
    CHECK(k->android_release == erel && k->kver_major == maj && k->kver_minor == min,
          "select(rel=%d,%d.%d) -> android%d-%d.%d", rel, maj, min,
          k->android_release, k->kver_major, k->kver_minor);
}

static void test_regression_generic(void) {
    printf("[R] regression: upstream generic selection unchanged\n");
    /* Every upstream table combination selects its own exact entry. */
    expect_select(12, 5, 10, 12);
    expect_select(13, 5, 10, 13);
    expect_select(13, 5, 15, 13);
    expect_select(14, 5, 15, 14);
    expect_select(14, 6, 1, 14);
    expect_select(15, 6, 6, 15);
    expect_select(16, 6, 12, 16);
    expect_select(17, 6, 18, 17);

    /* Documented ZZIC behaviour: uname parse -> android15/6.6 generic family. */
    int rel = 0, maj = 0, min = 0;
    int rc = dfr_parse_kernel_versions(
        "6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k", &rel, &maj, &min);
    CHECK(rc == 0 && rel == 15 && maj == 6 && min == 6,
          "ZZIC uname parses to android15/6.6 (rc=%d rel=%d %d.%d)", rc, rel, maj, min);
    const struct KoImage *k = dfr_select_ko_image(UPSTREAM_TABLE, TABLE_N, rel, maj, min);
    CHECK(k && k->android_release == 15 && k->kver_major == 6 && k->kver_minor == 6,
          "ZZIC generic family selects android15-6.6 (family, NOT identity)");

    /* Fallback: kver match, android_release absent -> first (maj,min) entry. */
    k = dfr_select_ko_image(UPSTREAM_TABLE, TABLE_N, 99, 5, 15);
    CHECK(k && k->kver_major == 5 && k->kver_minor == 15,
          "unknown android on known 5.15 kernel -> fallback to a 5.15 module");

    /* Unknown kernel major/minor -> no module. */
    k = dfr_select_ko_image(UPSTREAM_TABLE, TABLE_N, 17, 6, 99);
    CHECK(k == NULL, "unknown kernel 6.99 -> NULL (no module)");
}

static void test_sha256(void) {
    printf("[S] sha256 known-answer\n");
    dfr_sha256_ctx c; uint8_t d[32]; char hex[65];
    dfr_sha256_init(&c);
    dfr_sha256_update(&c, "abc", 3);
    dfr_sha256_final(&c, d);
    dfr_sha256_hex(d, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "sha256(\"abc\") = %s", hex);

    dfr_sha256_init(&c);
    dfr_sha256_final(&c, d);
    dfr_sha256_hex(d, hex);
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
          "sha256(\"\") = %s", hex);
}

/*
 * [G] Gate-G chain-level module policy. Every page-cache stage consults this,
 * so the decision must be exercised off-device: a regression here re-opens the
 * ZZIC path silently.
 */
static void test_module_policy(void) {
    printf("[G] Gate G: chain-level module policy\n");
    struct TargetProfile p;

    /* Unrelated devices keep upstream behaviour: Gate G never applies. */
    dfr_module_policy v = dfr_module_policy_eval(DFR_TARGET_UPSTREAM_GENERIC, &DFR_PROFILE_ZZIC);
    CHECK(v == DFR_MODULE_POLICY_NOT_APPLICABLE && dfr_module_policy_permits(v),
          "upstream generic device -> NOT_APPLICABLE, permitted (%s)",
          dfr_module_policy_name(v));

    /* A MISMATCH never reaches Gate G, but must not read as permitted either. */
    v = dfr_module_policy_eval(DFR_TARGET_MISMATCH, &DFR_PROFILE_ZZIC);
    CHECK(v == DFR_MODULE_POLICY_NOT_APPLICABLE,
          "MISMATCH -> NOT_APPLICABLE (refused earlier, by Gate A) (%s)",
          dfr_module_policy_name(v));

    /* The shipped profile now pins a validated module, so the policy allows the
     * stage to proceed - to the digest binding in patch_ko(), which is what
     * actually compares the bytes. This assertion tracks the shipped profile on
     * purpose: if the three ko_* fields are ever cleared, or set inconsistently,
     * it changes here rather than silently on a device. */
    v = dfr_module_policy_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC);
    CHECK(v == DFR_MODULE_POLICY_ALLOW && dfr_module_policy_permits(v),
          "shipped profile on ZZIC -> ALLOW, all three ko_* fields set (%s)",
          dfr_module_policy_name(v));

    /* Clearing the flag refuses again, whatever else stays pinned. The policy
     * never infers permission from a digest that happens to be there. */
    p = DFR_PROFILE_ZZIC;
    p.ko_zzic_verified = 0;
    v = dfr_module_policy_eval(DFR_TARGET_S25U_ZZIC, &p);
    CHECK(v == DFR_MODULE_POLICY_REFUSE_UNVERIFIED && !dfr_module_policy_permits(v),
          "ko_zzic_verified=0 with a digest pinned -> REFUSE_UNVERIFIED (%s)",
          dfr_module_policy_name(v));

    /* A bare flag is not evidence: no digest, no filename -> still refused. */
    p = DFR_PROFILE_ZZIC;
    p.ko_zzic_verified = 1;
    p.ko_sha256 = NULL;
    p.ko_filename = NULL;
    v = dfr_module_policy_eval(DFR_TARGET_S25U_ZZIC, &p);
    CHECK(v == DFR_MODULE_POLICY_REFUSE_NO_DIGEST && !dfr_module_policy_permits(v),
          "ko_zzic_verified=1 with no ko_sha256 -> REFUSE_NO_DIGEST (%s)",
          dfr_module_policy_name(v));

    /* An empty-string digest is "not pinned", not "pinned to nothing". */
    p = DFR_PROFILE_ZZIC;
    p.ko_zzic_verified = 1;
    p.ko_sha256 = "";
    p.ko_filename = "dirtyfrag-zzic.ko";
    v = dfr_module_policy_eval(DFR_TARGET_S25U_ZZIC, &p);
    CHECK(v == DFR_MODULE_POLICY_REFUSE_NO_DIGEST,
          "empty ko_sha256 -> REFUSE_NO_DIGEST (%s)", dfr_module_policy_name(v));

    /* All three fields go together: a digest without a filename is refused. */
    p = DFR_PROFILE_ZZIC;
    p.ko_zzic_verified = 1;
    p.ko_sha256 = "00112233445566778899aabbccddeeff"
                  "00112233445566778899aabbccddeeff";
    p.ko_filename = NULL;
    v = dfr_module_policy_eval(DFR_TARGET_S25U_ZZIC, &p);
    CHECK(v == DFR_MODULE_POLICY_REFUSE_NO_FILENAME && !dfr_module_policy_permits(v),
          "digest without ko_filename -> REFUSE_NO_FILENAME (%s)",
          dfr_module_policy_name(v));

    /* All three present -> the policy allows the chain; the BYTE binding is
     * still checked separately by patch_ko(), which is the only holder of the
     * selected payload. */
    p.ko_filename = "dirtyfrag-zzic.ko";
    v = dfr_module_policy_eval(DFR_TARGET_S25U_ZZIC, &p);
    CHECK(v == DFR_MODULE_POLICY_ALLOW && dfr_module_policy_permits(v),
          "all three ko_* fields set -> ALLOW (byte binding still owed) (%s)",
          dfr_module_policy_name(v));

    /* A ZZIC classification with nothing to consult is a refusal, not a pass. */
    v = dfr_module_policy_eval(DFR_TARGET_S25U_ZZIC, NULL);
    CHECK(!dfr_module_policy_permits(v),
          "ZZIC with a NULL profile -> refused (%s)", dfr_module_policy_name(v));
}

/* ---- [V] vendor-ELF provenance (Gate B redesign) ---- */

/* The observation the ZZIC device actually produces: every AVB element agrees,
 * and the direct read is denied with EACCES from this SELinux domain. */
static struct VendorObservation zzic_vendor_observed(void) {
    struct VendorObservation o;
    memset(&o, 0, sizeof(o));
    o.verified_boot_state = "green";
    o.vbmeta_device_state = "locked";
    o.flash_locked        = "1";
    o.verity_mode         = "enforcing";
    o.vbmeta_digest       =
        "23a0e0b0a5b421d5a75b62de40edb37489a4e6d441d54e58ee6f930c1a9a3f62";
    o.vbmeta_avb_version  = "1.2";
    o.vbmeta_hash_alg     = "sha256";
    o.vendor_fstype       = "erofs";
    o.vendor_ro           = 1;
    o.direct_sha256       = NULL;      /* open(2) denied */
    o.direct_errno        = DFR_EACCES;
    o.size                = -1;        /* getattr denied too */
    o.context             = NULL;
    return o;
}

static void test_vendor_provenance(void) {
    printf("[V] vendor-ELF provenance\n");
    struct VendorProvMatch m;
    struct TargetProfile p;
    struct VendorObservation o;
    dfr_vendor_prov v;

    /* An unrelated device never reaches this gate. */
    o = zzic_vendor_observed();
    v = dfr_vendor_provenance_eval(DFR_TARGET_UPSTREAM_GENERIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_NOT_APPLICABLE && dfr_vendor_prov_permits(v),
          "upstream generic -> NOT_APPLICABLE (%s)", dfr_vendor_prov_name(v));

    /* THE case the v2.0.2 physical run hit: EACCES + a complete AVB chain.
     * This must PASS, or the ZZIC path is unrunnable by construction. */
    o = zzic_vendor_observed();
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_PASS_AVB && dfr_vendor_prov_permits(v) && m.chain_ok,
          "EACCES + complete AVB chain -> PASS_AVB (%s)", dfr_vendor_prov_name(v));

    /* A domain that CAN read it still gets the strongest proof, not a downgrade. */
    o = zzic_vendor_observed();
    o.direct_sha256 = DFR_PROFILE_ZZIC.vendor_target_sha256;
    o.direct_errno = 0;
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_PASS_DIRECT && dfr_vendor_prov_permits(v),
          "readable + matching digest -> PASS_DIRECT (%s)", dfr_vendor_prov_name(v));

    /* Readable and WRONG is the one thing no provenance can excuse. */
    o = zzic_vendor_observed();
    o.direct_sha256 = "00112233445566778899aabbccddeeff"
                      "00112233445566778899aabbccddeeff";
    o.direct_errno = 0;
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_DIRECT_MISMATCH && !dfr_vendor_prov_permits(v),
          "readable + wrong digest -> FAIL_DIRECT_MISMATCH (%s)", dfr_vendor_prov_name(v));

    /* Unreadable for any OTHER reason is a fault, not the documented policy. */
    o = zzic_vendor_observed();
    o.direct_errno = 2; /* ENOENT */
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_UNREADABLE && !dfr_vendor_prov_permits(v),
          "unreadable with ENOENT -> FAIL_UNREADABLE (%s)", dfr_vendor_prov_name(v));

    /* --- every chain element, one at a time --- */
    {
        int i;
        struct VendorObservation t;
        const char *names[] = {
            "verifiedbootstate!=green", "device_state!=locked",
            "flash.locked!=1", "veritymode!=enforcing",
            "vbmeta.digest differs", "avb_version differs",
            "hash_alg differs", "/vendor not erofs",
        };
        const char *bads[] = {
            "orange", "unlocked", "0", "logging",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1.1", "sha512", "ext4",
        };
        for (i = 0; i < 8; i++) {
            t = zzic_vendor_observed();
            switch (i) {
                case 0: t.verified_boot_state = bads[i]; break;
                case 1: t.vbmeta_device_state = bads[i]; break;
                case 2: t.flash_locked = bads[i]; break;
                case 3: t.verity_mode = bads[i]; break;
                case 4: t.vbmeta_digest = bads[i]; break;
                case 5: t.vbmeta_avb_version = bads[i]; break;
                case 6: t.vbmeta_hash_alg = bads[i]; break;
                case 7: t.vendor_fstype = bads[i]; break;
            }
            v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &t, &m);
            CHECK(v == DFR_VENDOR_PROV_FAIL_CHAIN && !dfr_vendor_prov_permits(v),
                  "%s -> FAIL_CHAIN (%s)", names[i], dfr_vendor_prov_name(v));
        }
    }

    /* /vendor mounted rw, and /vendor whose mount could not be determined. */
    o = zzic_vendor_observed();
    o.vendor_ro = 0;
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_CHAIN, "/vendor mounted rw -> FAIL_CHAIN (%s)",
          dfr_vendor_prov_name(v));
    o = zzic_vendor_observed();
    o.vendor_ro = -1;
    o.vendor_fstype = NULL;
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_CHAIN, "/vendor mount unknown -> FAIL_CHAIN (%s)",
          dfr_vendor_prov_name(v));

    /* An absent property is never "equal to the pinned value". */
    o = zzic_vendor_observed();
    o.vbmeta_digest = NULL;
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_CHAIN, "unset vbmeta.digest -> FAIL_CHAIN (%s)",
          dfr_vendor_prov_name(v));

    /* Observational anchors: unavailable is SKIP, available-and-wrong is FAIL. */
    o = zzic_vendor_observed();
    o.size = DFR_PROFILE_ZZIC.vendor_target_size;
    o.context = DFR_PROFILE_ZZIC.vendor_target_context;
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_PASS_AVB && m.size_checked && m.context_checked,
          "size+label available and matching -> PASS_AVB, both checked (%s)",
          dfr_vendor_prov_name(v));
    o.size = 1;
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_CHAIN, "wrong vendor size -> FAIL_CHAIN (%s)",
          dfr_vendor_prov_name(v));
    o = zzic_vendor_observed();
    o.context = "u:object_r:system_file:s0";
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_CHAIN, "wrong vendor label -> FAIL_CHAIN (%s)",
          dfr_vendor_prov_name(v));
    o = zzic_vendor_observed();
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(!m.size_checked && !m.context_checked && m.size_ok && m.context_ok,
          "size/label denied -> not checked, and absence is not agreement");

    /* A half-pinned profile refuses rather than validating the half it has. */
    p = DFR_PROFILE_ZZIC;
    p.vbmeta_digest = NULL;
    o = zzic_vendor_observed();
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &p, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_NO_PIN && !dfr_vendor_prov_permits(v),
          "profile with no vbmeta_digest -> FAIL_NO_PIN (%s)", dfr_vendor_prov_name(v));
    p = DFR_PROFILE_ZZIC;
    p.verity_mode = "";
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &p, &o, &m);
    CHECK(v == DFR_VENDOR_PROV_FAIL_NO_PIN,
          "empty verity_mode is unpinned, not pinned-to-empty (%s)",
          dfr_vendor_prov_name(v));

    /* Nothing to consult is a refusal. */
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, NULL, &m);
    CHECK(!dfr_vendor_prov_permits(v), "NULL observation -> refused (%s)",
          dfr_vendor_prov_name(v));
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, NULL, &o, &m);
    CHECK(!dfr_vendor_prov_permits(v), "NULL profile -> refused (%s)",
          dfr_vendor_prov_name(v));

    /* The shipped profile must pin the whole chain: the ZZIC target is
     * otherwise refused at this gate no matter what the device reports. */
    o = zzic_vendor_observed();
    v = dfr_vendor_provenance_eval(DFR_TARGET_S25U_ZZIC, &DFR_PROFILE_ZZIC, &o, &m);
    CHECK(v != DFR_VENDOR_PROV_FAIL_NO_PIN,
          "shipped profile pins every provenance anchor (%s)", dfr_vendor_prov_name(v));
}

/* ---- [P] shipped-profile invariants ---- */

static int is_lower_hex64(const char *s) {
    int i;
    if (s == NULL) return 0;
    for (i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return s[64] == 0;
}

static void test_profile_invariants(void) {
    const struct TargetProfile *p = &DFR_PROFILE_ZZIC;
    printf("[P] shipped-profile invariants\n");

    /*
     * crash_dump64 is patch #1's target and IS readable from the chain's
     * domain, so it stays a direct runtime hash - which means it must be
     * pinned, or gate_hash() refuses the whole chain before patch #1.
     * Value captured from the ZZIC device during the v2.0.2-zzic run.
     */
    CHECK(is_lower_hex64(p->crashdump_sha256),
          "crashdump_sha256 is pinned as 64 lowercase hex chars (%s)",
          p->crashdump_sha256 ? p->crashdump_sha256 : "<null>");
    CHECK(dfr_streq(p->crashdump_sha256,
                    "9249d66445837c52322c2c86ee62efa64e49a7c1b72084c1ce98f72c12a1151f"),
          "crashdump_sha256 is the value captured on ZZIC hardware");
    CHECK(is_lower_hex64(p->vendor_target_sha256) &&
          is_lower_hex64(p->libc_sha256) && is_lower_hex64(p->libcxx_sha256),
          "every written artefact's digest is pinned as 64 lowercase hex chars");
    CHECK(is_lower_hex64(p->vbmeta_digest),
          "vbmeta_digest is pinned as 64 lowercase hex chars");

    /* Gate G boundary G1: a module built against this exact kernel is now
     * pinned. The three fields move together or not at all, which is the whole
     * invariant - so assert the conjunction rather than the flag, in either
     * direction. A future revert to UNVERIFIED must clear all three, and this
     * fails if it clears only some. */
    CHECK((p->ko_zzic_verified == 1 && p->ko_filename != NULL &&
           p->ko_sha256 != NULL) ||
          (p->ko_zzic_verified == 0 && p->ko_filename == NULL &&
           p->ko_sha256 == NULL),
          "the three ko_* fields move together: verified=%d filename=%s digest=%s",
          p->ko_zzic_verified,
          p->ko_filename ? p->ko_filename : "<none>",
          p->ko_sha256 ? "pinned" : "<none>");
    CHECK(p->ko_zzic_verified == 1 &&
          dfr_streq(p->ko_filename, "dirtyfrag-android15-6.6-S938BXXUCZZIC.ko") &&
          is_lower_hex64(p->ko_sha256),
          "the pinned module is the exact-kernel one, digest as 64 lowercase hex");
}

/* ---- [M] /proc/self/mountinfo parsing ---- */
static void test_mountinfo(void) {
    printf("[M] mountinfo parsing\n");
    char fs[64];
    int ro;
    /* Real ZZIC shape, optional fields present, "-" separator not at a fixed index. */
    const char *mi =
        "24 23 0:22 / /dev rw,nosuid,relatime - tmpfs tmpfs rw,seclabel,mode=755\n"
        "77 23 254:17 / /vendor ro,seclabel,relatime,ro shared:12 master:3 - erofs "
        "/dev/block/dm-17 ro,user_xattr\n"
        "78 23 254:18 / /system ro,seclabel,relatime - erofs /dev/block/dm-16 ro\n";
    CHECK(dfr_mountinfo_lookup(mi, "/vendor", fs, sizeof(fs), &ro) == 1 &&
          strcmp(fs, "erofs") == 0 && ro == 1,
          "/vendor -> erofs, ro=1 (got fs=%s ro=%d)", fs, ro);
    CHECK(dfr_mountinfo_lookup(mi, "/dev", fs, sizeof(fs), &ro) == 1 &&
          strcmp(fs, "tmpfs") == 0 && ro == 0,
          "/dev -> tmpfs, ro=0 (got fs=%s ro=%d)", fs, ro);
    CHECK(dfr_mountinfo_lookup(mi, "/product", fs, sizeof(fs), &ro) == 0 && ro == -1,
          "absent mountpoint -> not found, ro=-1 (ro=%d)", ro);
    /* A later mount over the same point is the effective one. */
    const char *shadow =
        "77 23 254:17 / /vendor ro,seclabel - erofs /dev/block/dm-17 ro\n"
        "99 23 0:44 / /vendor rw,seclabel - overlay overlay rw\n";
    CHECK(dfr_mountinfo_lookup(shadow, "/vendor", fs, sizeof(fs), &ro) == 1 &&
          strcmp(fs, "overlay") == 0 && ro == 0,
          "last mount wins: /vendor -> overlay, ro=0 (got fs=%s ro=%d)", fs, ro);
    /* A mountpoint that only PREFIXES the query must not match. */
    const char *prefix = "77 23 254:17 / /vendor_dlkm ro,seclabel - erofs /dev/x ro\n";
    CHECK(dfr_mountinfo_lookup(prefix, "/vendor", fs, sizeof(fs), &ro) == 0,
          "/vendor_dlkm does not answer for /vendor");
    CHECK(dfr_mountinfo_lookup(NULL, "/vendor", fs, sizeof(fs), &ro) == 0,
          "NULL mountinfo -> not found");
}

int main(void) {
    printf("DFReroot target-profile test suite\n\n");
    test_target_detection();
    printf("\n");
    test_regression_generic();
    printf("\n");
    test_module_policy();
    printf("\n");
    test_vendor_provenance();
    printf("\n");
    test_profile_invariants();
    printf("\n");
    test_mountinfo();
    printf("\n");
    test_sha256();
    printf("\n%d/%d checks passed, %d failed\n", g_total - g_fail, g_total, g_fail);
    return g_fail == 0 ? 0 : 1;
}
