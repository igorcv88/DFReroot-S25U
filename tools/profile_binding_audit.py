#!/usr/bin/env python3
"""
Profile-to-module cryptographic binding audit (dossier section 39).

`ko_verified` is a boolean, and a boolean is not evidence. This tool
enforces, in CI, the same invariant the runtime enforces in patch_ko():

    ko_verified == 1
      IMPLIES ko_sha256 is pinned
      AND     ko_filename names a module that is actually bundled
      AND     SHA-256(those bundled bytes) == ko_sha256

It also checks the reverse direction: while the flag is 0, no stale digest may
be left pinned, so a later reviewer cannot mistake a leftover hash for evidence.

Additionally verifies that the C profile and tools/zzic_profile.json agree on
every identity field they share - a drift between the runtime gate and the
offline tools would mean two different definitions of "the target".

    tools/profile_binding_audit.py [--json]

Exit code 0 = invariants hold, 1 = violated.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ko_audit's COMPATIBLE verdict is the only thing that authorises setting
# ko_verified=1, so this tool also guards the rule that verdict rests on.
sys.path.insert(0, HERE)
import ko_audit  # noqa: E402
PROFILE_C = os.path.join(ROOT, "app", "src", "main", "jni", "target_profile.c")
JNI_DIR = os.path.join(ROOT, "app", "src", "main", "jni")
DFR_JAVA_DIR = os.path.join(ROOT, "app", "src", "main", "java",
                            "com", "polygraphene", "df", "reroot")
PROFILE_JSON = os.path.join(HERE, "zzic_profile.json")
EXP_C = os.path.join(ROOT, "app", "src", "main", "jni", "exp.c")

# The committed Gate-G evidence: the derived ZZIC CRC table and the provenance
# that binds every one of them to witness bytes. ko_audit REQUIRES the record for
# a table carrying the derived marker, so naming the table alone would not be
# enough to re-establish the verdict here.
GATE_G_DIR = os.path.join(ROOT, "evidence", "zzic", "gate-g")
DERIVED_SYMVERS = os.path.join(GATE_G_DIR, "ZZIC-derived-minimal.symvers")
DERIVED_PROVENANCE = os.path.join(GATE_G_DIR, "ZZIC-modversion-provenance.json")

# Runtime sources of both apps: everything that ships inside an APK. Build
# scripts and the offline tools are excluded on purpose - they never run on the
# device. The removed override token is rejected anywhere in here.
RUNTIME_ROOTS = [
    os.path.join(ROOT, "app", "src", "main"),
    os.path.join(ROOT, "installer", "src", "main"),
]
# The stricter "no world-writable staging path" rule applies to DFReroot only:
# that is the app that evaluates Gate G and performs the page-cache writes.
# DFInstaller never reaches Gate G, and its CLI usage comments legitimately show
# /data/local/tmp paths for a manually sideloaded APK.
CHAIN_ROOTS = [os.path.join(ROOT, "app", "src", "main")]
RUNTIME_EXTS = (".c", ".h", ".kt", ".java", ".S")

# The token PR #5 removed. Kept here as a named constant so its reintroduction is
# caught by name as well as by the broader mechanism check below.
LEGACY_BYPASS_TOKEN = "dfr_allow_unverified_ko"

# Any world-writable staging path referenced from runtime code.
TMP_PATH_RE = re.compile(r"/data/local/tmp[\w./-]*")

# Every page-cache corruption stage in exp.c, each independently reachable.
PATCH_STAGES = ["patch_ko", "patch_libc", "patch_cxx"]

# The on-device collector, and every field the runtime identity gate compares. A
# field missing from the collector is a MISMATCH nobody can explain.
COLLECT_SH = os.path.join(HERE, "zzic_collect.sh")
COLLECTED_PROPS = [
    "ro.product.manufacturer", "ro.product.model", "ro.product.device",
    "ro.build.version.sdk", "ro.build.version.release", "ro.build.display.id",
    "ro.build.fingerprint", "ro.product.cpu.abi",
    "uname -r", "uname -v", "uname -m", "PAGESIZE",
    "/apex/com.android.runtime/bin/crash_dump64", "boot_id",
    # vendor-provenance inputs: every element dfr_vendor_provenance_eval()
    # compares must be printable by the same single collector run, or the
    # operator has no way to diff a FAIL_CHAIN against the profile.
    "ro.boot.verifiedbootstate", "ro.boot.vbmeta.device_state",
    "ro.boot.flash.locked", "ro.boot.veritymode", "ro.boot.vbmeta.digest",
    "ro.boot.vbmeta.avb_version", "ro.boot.vbmeta.hash_alg",
    "/proc/self/mountinfo", "/vendor/lib64/libstagefrighthw.so",
]


def rel(path):
    """Repo-relative path, so a violation message names a file a reader can open."""
    return os.path.relpath(path, ROOT)


def sources_under(roots):
    out = []
    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in sorted(filenames):
                if name.endswith(RUNTIME_EXTS):
                    out.append(os.path.join(dirpath, name))
    return sorted(out)


def stage_calls_policy(src, stage):
    """True if `stage`'s body in exp.c calls gate_module_policy().

    The body is taken from the function's opening line to the start of the next
    top-level definition, which is enough structure for this file's flat layout
    and avoids matching a call that merely sits somewhere else in the file.
    """
    m = re.search(r"^[A-Za-z_][\w \t*]*\b%s\s*\([^;]*\)\s*\{" % re.escape(stage),
                  src, flags=re.M)
    if not m:
        return False
    body = src[m.end():]
    nxt = re.search(r"^\}", body, flags=re.M)
    if nxt:
        body = body[:nxt.start()]
    return "gate_module_policy(" in body

# Fields compared between the C profile and the JSON profile.
SHARED_STRINGS = [
    "id", "manufacturer", "model", "device", "display", "fingerprint",
    "kernel_release", "kernel_version", "abi", "kernel_arch",
    "kernel_image_sha256", "btf_sha256", "crashdump_sha256",
    "vendor_target_sha256", "libc_sha256", "libcxx_sha256",
    "vbmeta_digest", "vbmeta_avb_version", "vbmeta_hash_alg",
    "verified_boot_state", "vbmeta_device_state", "flash_locked",
    "verity_mode", "vendor_fstype", "vendor_target_context",
    "network_stack_process", "network_stack_context", "post_root_record",
]
SHARED_INTS = ["sdk", "android_release", "page_size", "network_stack_uid",
               "vendor_mount_ro", "vendor_target_size", "kernelsu_version",
               "kernelsu_uapi_version", "post_root_selinux"]

# Artefact hashes that appear TWICE in zzic_profile.json: once as a top-level
# field mirrored from the C profile, and once keyed by the path it belongs to
# under "targets". The two are edited by hand at different moments (the device
# collector prints both lines), so a value updated in one place and not the
# other is the exact drift this check exists to catch - it would leave a tool
# validating one hash while the runtime pins another.
TARGET_PATH_FIELDS = {
    "/apex/com.android.runtime/bin/crash_dump64": "crashdump_sha256",
    "/vendor/lib64/libstagefrighthw.so": "vendor_target_sha256",
    "/system/lib64/libc.so": "libc_sha256",
    "/system/lib64/libc++.so": "libcxx_sha256",
}

# Provenance anchors that must ALL be pinned together. The runtime refuses with
# FAIL_NO_PIN when any of them is missing, so a profile that ships half a chain
# is a profile whose ZZIC path can never run - catch it here instead.
VENDOR_PROVENANCE_STRINGS = [
    "vendor_target_sha256", "vbmeta_digest", "vbmeta_avb_version",
    "vbmeta_hash_alg", "verified_boot_state", "vbmeta_device_state",
    "flash_locked", "verity_mode", "vendor_fstype",
]

# Artefacts the chain WRITES and therefore must have a pristine digest pinned
# for. gate_hash() treats an unpinned required artefact as a FAIL, so shipping
# one unpinned is shipping a build that cannot reach its own next boundary.
REQUIRED_ARTEFACT_HASHES = ["crashdump_sha256", "libc_sha256", "libcxx_sha256"]


def parse_c_profile(path):
    """Extract the DFR_PROFILE_ZZIC designated initialisers.

    Deliberately a small regex reader rather than a C parser: it only has to
    understand `.field = value,` with adjacent string-literal concatenation,
    which is the exact shape target_profile.c uses.
    """
    with open(path) as f:
        src = f.read()
    start = src.index("DFR_PROFILE_ZZIC")
    body = src[start:]
    body = body[body.index("{") + 1: body.index("\n};")]
    # strip comments so commented-out values never read as real ones
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)

    out = {}
    for m in re.finditer(r"\.(\w+)\s*=\s*(.*?)(?=,\s*\.\w+\s*=|,?\s*$)", body, flags=re.S):
        field, raw = m.group(1), m.group(2).strip().rstrip(",").strip()
        if raw == "NULL":
            out[field] = None
            continue
        lits = re.findall(r'"((?:[^"\\]|\.)*)"', raw)
        if lits:
            out[field] = "".join(lits)
            continue
        num = re.match(r"^(0x[0-9a-fA-F]+|-?\d+)[LlUu]*$", raw)
        if num:
            out[field] = int(num.group(1), 0)
            continue
        out[field] = raw
    return out


def audit():
    r = {"violations": [], "checks": {}}
    c = parse_c_profile(PROFILE_C)
    with open(PROFILE_JSON) as f:
        j = json.load(f)
    r["c_profile"] = c

    def fail(msg):
        r["violations"].append(msg)

    # exp.c is inspected by several checks below; read it once.
    try:
        with open(EXP_C, encoding="utf-8") as f:
            exp_src_holder = [f.read()]
    except OSError as ex:
        fail("cannot read %s: %s" % (rel(EXP_C), ex))
        exp_src_holder = [""]

    # --- the section 39 invariant -------------------------------------------
    verified = c.get("ko_verified")
    ko_sha = c.get("ko_sha256")
    ko_name = c.get("ko_filename")
    r["checks"]["ko_verified"] = verified
    r["checks"]["ko_filename"] = ko_name
    r["checks"]["ko_sha256_pinned"] = ko_sha

    if verified not in (0, 1):
        fail("ko_verified is %r; expected 0 or 1" % (verified,))
    elif verified == 1:
        if not ko_sha:
            fail("ko_verified=1 but ko_sha256 is not pinned "
                 "(a boolean is not evidence)")
        if not ko_name:
            fail("ko_verified=1 but ko_filename is not set")
        if ko_sha and ko_name:
            ko_path = os.path.join(JNI_DIR, os.path.basename(ko_name))
            if not os.path.exists(ko_path):
                fail("ko_filename=%s is not bundled at %s" % (ko_name, ko_path))
            else:
                with open(ko_path, "rb") as f:
                    actual = hashlib.sha256(f.read()).hexdigest()
                r["checks"]["ko_sha256_actual"] = actual
                if actual != ko_sha:
                    fail("bundled %s sha256=%s does not match pinned ko_sha256=%s"
                         % (ko_name, actual, ko_sha))
                else:
                    r["checks"]["ZZIC_MODULE_BINDING"] = "PASS"
                    # The digest proves the bundled bytes are the ones that were
                    # pinned. It says nothing about WHY they were pinned, and
                    # AGENTS.md 3.5 allows exactly one answer: a COMPATIBLE
                    # verdict from ko_audit against the exact kernel's CRCs. So
                    # re-run that verdict here, against the committed derived
                    # table and its provenance, rather than trusting that
                    # someone once did. A digest can be re-pinned to any file;
                    # this check refuses unless the file still wins the argument.
                    try:
                        full = ko_audit.audit(
                            ko_path,
                            symvers=DERIVED_SYMVERS,
                            provenance=DERIVED_PROVENANCE,
                            require_coverage=True)
                    except Exception as ex:
                        fail("ko_verified=1 but %s cannot be audited "
                             "against the derived ZZIC table: %s" % (ko_name, ex))
                        full = None
                    if full is not None:
                        got = full.get("MODULE_VS_ZZIC_KERNEL")
                        cov = full.get("MODVERSION_COVERAGE")
                        r["checks"]["ZZIC_MODULE_VERDICT"] = got
                        r["checks"]["ZZIC_MODULE_COVERAGE"] = cov
                        if got != "COMPATIBLE":
                            fail("ko_verified=1 but the bundled %s audits "
                                 "%r against the derived ZZIC table, not "
                                 "COMPATIBLE" % (ko_name, got))
                        if full.get("provenance_violations"):
                            fail("ko_verified=1 but the derived table's "
                                 "provenance does not hold up: %s"
                                 % full["provenance_violations"])
                        # Name the table the verdict rests on, per AGENTS.md 3.5:
                        # a Module.symvers carries no kernel release, so the
                        # digest is the only record of WHICH table decided it.
                        r["checks"]["ZZIC_MODULE_SYMVERS"] = "%s (%s)" % (
                            full.get("symvers_sha256"), full.get("symvers_kind"))
    else:
        # flag is 0: nothing may be pinned that could later be mistaken for proof
        if ko_sha:
            fail("ko_verified=0 but ko_sha256 is pinned (%s); "
                 "a stale digest reads as evidence it is not" % ko_sha)
        if ko_name:
            fail("ko_verified=0 but ko_filename is set (%s)" % ko_name)
        r["checks"]["ZZIC_MODULE_BINDING"] = "UNVERIFIED (fail-closed, as expected)"

    # --- the modversion coverage rule behind a COMPATIBLE verdict -----------
    # Only MODULE_VS_ZZIC_KERNEL=COMPATIBLE justifies moving the three ko_*
    # fields (AGENTS.md 3.5), so the rule that verdict rests on is guarded here
    # by exercising ko_audit on the bundled modules rather than by grepping its
    # source: a refactor that drops the coverage requirement still trips this.
    #
    # The hole being closed: comparing only the entries __versions HAPPENS to
    # contain is fail-open. An entries-only diff finds every present entry in
    # agreement and reads COMPATIBLE while the table says nothing about the rest.
    #
    # Note what the kernel actually does with such a hole, because AGENTS.md 3.5
    # used to state this wrongly and the fix matters here: check_version() warns
    # once and LETS THE LOAD PROCEED. The module is not unloadable - it loads
    # with that symbol unchecked, which is the silent ABI mismatch this gate
    # exists to prevent. So the refusal below is "unverified", not "unloadable".
    cov_reports = {}
    for ko_file in sorted(glob.glob(os.path.join(JNI_DIR, "dirtyfrag-android*.ko"))):
        base = os.path.basename(ko_file)
        try:
            rep = ko_audit.audit(ko_file)
            strict = ko_audit.audit(ko_file, require_coverage=True)
        except Exception as ex:  # a tool that cannot run is not a pass
            fail("ko_audit could not audit %s: %s" % (base, ex))
            continue
        cov = rep.get("MODVERSION_COVERAGE")
        missing = rep.get("modversion_missing_entries")
        if cov is None or missing is None:
            fail("ko_audit no longer reports modversion coverage for %s; the "
                 "COMPATIBLE verdict would rest on an entries-only diff" % base)
            continue
        # Only a module built for the ZZIC kernel family is a ZZIC candidate;
        # the upstream modules for other families stay N/A by design, and
        # demanding INCOMPATIBLE from them would read as "evaluated and rejected
        # for its own kernel", which is not what was measured.
        candidate = bool(rep.get("vermagic_base_ok"))
        cov_reports[base] = "%s  [%s]" % (
            cov, "ZZIC candidate" if candidate else "other kernel family")
        if missing:
            # A named hole must be fatal somewhere, or naming it buys nothing.
            if str(cov).startswith("COMPLETE"):
                fail("%s: coverage reads COMPLETE while %d import(s) have no "
                     "__versions entry (%s)" % (base, len(missing),
                                                ", ".join(missing)))
            if candidate and strict.get("MODULE_VS_ZZIC_KERNEL") != "INCOMPATIBLE":
                fail("%s: %d import(s) have no __versions entry but "
                     "--require-modversion-coverage still yields %r; a module "
                     "whose version checks the kernel would skip must not pass"
                     % (base, len(missing), strict.get("MODULE_VS_ZZIC_KERNEL")))
        # An imported symbol reported as "not imported" is a false label on
        # exactly the hole that matters (AGENTS.md 3.7: signals never collapsed).
        for sym, props in (rep.get("symbols_of_interest") or {}).items():
            if props.get("SYMBOL_IMPORTED_BY_MODULE") and \
                    "not imported" in str(props.get("MODVERSION_MATCH")):
                fail("%s: %s is imported but MODVERSION_MATCH reads %r"
                     % (base, sym, props.get("MODVERSION_MATCH")))
    if not cov_reports:
        fail("no dirtyfrag-android*.ko is bundled; the Gate-G coverage rule "
             "has nothing to guard")
    r["checks"]["modversion_coverage"] = cov_reports

    def dfr_source(name):
        """Read one shipped DFReroot Kotlin/Java source, or fail loudly."""
        path = os.path.join(ROOT, "app", "src", "main", "java", "com",
                            "polygraphene", "df", "reroot", name)
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except OSError as ex:
            fail("cannot read %s: %s" % (name, ex))
            return ""

    main_src_holder = [dfr_source("MainActivity.kt")]
    coord_src = dfr_source("DfrRootCoordinator.kt")
    autoroot_policy_src = dfr_source("AutoRootPolicy.java")
    autoroot_store_src = dfr_source("AutoRootStore.kt")
    autoroot_service_src = dfr_source("DfrAutoRootService.kt")
    soft_reboot_policy_src = dfr_source("SoftRebootPolicy.java")
    soft_reboot_receiver_src = dfr_source("DfrSoftRebootReceiver.kt")
    notifier_src = dfr_source("RootNotifier.kt")
    boot_receiver_src = dfr_source("DfrBootReceiver.kt")

    # --- the ksud that gets handed uid 0 -----------------------------------
    # Same invariant shape as the module's, and for the same reason: the asset is
    # an opaque 6.6 MB binary, so "a ksud is bundled" is not evidence that THIS
    # one is. Unpinned is allowed and means KsudStage refuses to stage; pinned
    # must match the bytes that actually ship.
    ksud_sha_c, ksud_sha_j = c.get("ksud_sha256"), j.get("ksud_sha256")
    ksud_size_c, ksud_size_j = c.get("ksud_size"), j.get("ksud_size")
    r["checks"]["ksud_sha256_pinned"] = ksud_sha_c
    if ksud_sha_c != ksud_sha_j:
        fail("ksud_sha256 drift: C=%r json=%r" % (ksud_sha_c, ksud_sha_j))
    if ksud_size_c != ksud_size_j:
        fail("ksud_size drift: C=%r json=%r" % (ksud_size_c, ksud_size_j))
    ksud_asset = os.path.join(ROOT, "app", "src", "main", "assets", "ksud")
    if ksud_sha_c:
        if not ksud_size_c:
            fail("ksud_sha256 is pinned but ksud_size is not; a truncated read "
                 "would read as the wrong binary instead of as truncation")
        if not os.path.exists(ksud_asset):
            fail("ksud_sha256 is pinned but app/src/main/assets/ksud is absent")
        else:
            with open(ksud_asset, "rb") as f:
                blob = f.read()
            actual = hashlib.sha256(blob).hexdigest()
            r["checks"]["ksud_sha256_actual"] = actual
            r["checks"]["ksud_size_actual"] = len(blob)
            if actual != ksud_sha_c:
                fail("bundled assets/ksud sha256=%s does not match pinned "
                     "ksud_sha256=%s" % (actual, ksud_sha_c))
            elif ksud_size_c and len(blob) != ksud_size_c:
                fail("bundled assets/ksud is %d bytes, pinned ksud_size=%s"
                     % (len(blob), ksud_size_c))
            else:
                r["checks"]["ZZIC_KSUD_BINDING"] = "PASS"
            # The whole point of the dfreroot staging contract: this binary must
            # stage from a path this app is allowed to name.
            if b"/data/system/dfreroot-ksud" not in blob:
                fail("the bundled ksud does not contain /data/system/dfreroot-ksud;"
                     " it is not the dfreroot staging-contract build")
            if b"/data/local/tmp/.ksud-stage" in blob:
                fail("the bundled ksud still stages from the world-writable "
                     "/data/local/tmp/.ksud-stage; that is the contract AGENTS.md "
                     "3.6 exists to keep out of this app")
            for signal in (
                    b"/data/system/dfreroot-post-root",
                    b"/sys/fs/selinux/enforce",
                    b"/system/bin/setenforce",
                    b"POST_ROOT_KSU_CONTROL=PASS",
                    b"POST_ROOT_KSU_CONTROL_AFTER_RESTORE=PASS",
                    b"SELINUX_RESTORE=PASS",
                    b"POST_ROOT_COMPLETE=PASS"):
                if signal not in blob:
                    fail("the bundled ksud lacks the DFR post-root contract "
                         "signal %r" % signal.decode("ascii"))
    elif ksud_size_c:
        fail("ksud_size is pinned (%s) while ksud_sha256 is not; a size alone is "
             "not identity" % ksud_size_c)
    else:
        r["checks"]["ZZIC_KSUD_BINDING"] = "UNVERIFIED (fail-closed, as expected)"

    # The RMG ksud takes its staging path from stage_daemon_from(), compiled in.
    # It has no --stage-from option, and clap rejects an unknown long option, so
    # passing one would make late-load exit on a usage error before doing
    # anything - and the failure would look like the hop failing.
    s1 = os.path.join(ROOT, "app", "src", "main", "jni", "stage1.S")
    try:
        with open(s1, encoding="utf-8") as f:
            s1_src = f.read()
    except OSError as ex:
        fail("cannot read stage1.S: %s" % ex)
        s1_src = ""
    s1_code = re.sub(r"/\*.*?\*/", "", s1_src, flags=re.S)
    s1_code = re.sub(r"//[^\n]*", "", s1_code)
    if "--stage-from" in s1_code:
        fail("stage1.S passes --stage-from, which the RMG ksud does not accept; "
             "clap would reject it and late-load would never run")
    r["checks"]["stage2_argv_stage_from"] = "absent"

    # A pin nothing compares is dead weight, so KsudStage must still verify.
    ks = os.path.join(ROOT, "app", "src", "main", "java", "com", "polygraphene",
                      "df", "reroot", "KsudStage.kt")
    try:
        with open(ks, encoding="utf-8") as f:
            ks_src = f.read()
    except OSError as ex:
        fail("cannot read KsudStage.kt: %s" % ex)
        ks_src = ""
    if ksud_sha_c and ksud_sha_c not in ks_src:
        fail("KsudStage.kt does not carry the pinned ksud digest, so it cannot "
             "be comparing the bytes it stages")
    for marker in ("KSUD_IDENTITY=PASS", "KSUD_STAGED_VERIFY=PASS"):
        if marker not in ks_src:
            fail("KsudStage.kt no longer emits %s; the daemon would be staged "
                 "without a verified identity" % marker)
    # Strip comments first: a comment explaining why the fallback was removed
    # still contains its name, and this guard is about code.
    def code_only(src):
        out = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
        return re.sub(r"//[^\n]*", "", out)

    if "libksud.so" in code_only(ks_src) \
            or "libksud.so" in code_only(main_src_holder[0]):
        fail("the manager-app libksud.so fallback is back; it stages unpinned "
             "bytes from a third-party package into a uid-0 handoff")

    # --- DFR-only same-boot post-root contract ----------------------------
    post_status = os.path.join(ROOT, "app", "src", "main", "java", "com",
                               "polygraphene", "df", "reroot",
                               "PostRootStatus.java")
    try:
        with open(post_status, encoding="utf-8") as f:
            post_src = f.read()
    except OSError as ex:
        fail("cannot read PostRootStatus.java: %s" % ex)
        post_src = ""

    path_match = re.search(r'PATH\s*=\s*"([^"]+)"', post_src)
    ksu_match = re.search(r'EXPECTED_KSU_VERSION\s*=\s*(\d+)', post_src)
    uapi_match = re.search(r'EXPECTED_UAPI_VERSION\s*=\s*(\d+)', post_src)
    java_contract = {
        "post_root_record": path_match.group(1) if path_match else None,
        "kernelsu_version": int(ksu_match.group(1)) if ksu_match else None,
        "kernelsu_uapi_version": int(uapi_match.group(1)) if uapi_match else None,
    }
    for field, value in java_contract.items():
        if value != c.get(field) or value != j.get(field):
            fail("post-root contract drift for %s: Java=%r C=%r json=%r"
                 % (field, value, c.get(field), j.get(field)))
    if c.get("post_root_selinux") != 1:
        fail("post_root_selinux is %r; final success requires exact read-back 1"
             % c.get("post_root_selinux"))
    if "liveSelinux != 1" not in post_src or "stale boot_id" not in post_src:
        fail("PostRootStatus no longer refuses stale boots or live SELinux != 1")
    main_src = main_src_holder[0]
    # The decision moved into DfrRootCoordinator when the boot service became a
    # second caller of it. Kotlin cannot be unit-tested here (AGENTS.md 5), so the
    # guard follows the decision rather than staying pointed at the old file.
    for signal in (
            "val success = runResult == 0 && postRootComplete && liveSelinux == 1",
            "PostRootStatus.evaluate(record, bootId, liveSelinux)",
            "ROOT_RESULT=SUCCESS"):
        if signal not in coord_src:
            fail("DfrRootCoordinator post-root fail-closed signal missing: %r" % signal)
    # ... and both entry points must go through it rather than re-implementing it.
    for name, src in (("MainActivity.kt", main_src),
                      ("DfrAutoRootService.kt", autoroot_service_src)):
        if "DfrRootCoordinator.run(" not in src:
            fail("%s does not run the chain through DfrRootCoordinator; a second "
                 "copy of the sequence is a second place a gate can be forgotten"
                 % name)
        if "PostRootStatus.evaluate(" in src:
            fail("%s evaluates the post-root record itself instead of using the "
                 "shared coordinator verdict" % name)
    # The single process-wide owner is what stops a click and a boot trigger from
    # both reaching transaction 5, and the CONTROLLER deadline is what stops an
    # indefinite wait. Both now live in pure classes so the race and the timeout
    # are host-tested (tools/tests/RunHandoffTest.java); the coordinator must
    # still be the thing that uses them.
    if "guard.tryAcquire(who)" not in coord_src or "guard.release()" not in coord_src:
        fail("DfrRootCoordinator no longer takes a single process-wide run owner")
    if "controllerBox.await(" not in coord_src:
        fail("DfrRootCoordinator no longer waits for the CONTROLLER with a deadline")
    guard_src = dfr_source("RunGuard.java")
    box_src = dfr_source("AwaitBox.java")
    if "compareAndSet(null, who)" not in guard_src:
        fail("RunGuard no longer claims the run atomically")
    if "deadline - System.currentTimeMillis()" not in box_src \
            or "if (left <= 0) return null" not in box_src:
        fail("AwaitBox no longer refuses on its deadline; a missing CONTROLLER "
             "would wait forever instead of refusing before the native run")
    # Neither caller may reach the chain without staged, verified ksud bytes or
    # without the second-run refusal.
    for signal in ("KsudStage.stageFromAssets(context)",
                   "KSUD_STAGED_VERIFY=PASS",
                   "markerState()"):
        if signal not in coord_src:
            fail("DfrRootCoordinator no longer enforces %r before the hop" % signal)
    r["checks"]["post_root_contract"] = java_contract

    # --- the version exists in exactly one place, and it is not the tree ----
    # It used to be four literals in two build files, hand-edited before each
    # dispatch, and every way of getting that wrong happened: the installer left
    # a version behind while the app moved, a tag naming a version the tree did
    # not carry, a tag naming one it already carried. So the literals are gone -
    # tools/resolve_release_version.sh derives the version per run and the
    # workflow injects one pair into both modules.
    #
    # What has to be checked now is not agreement between two numbers but that
    # the single source is still wired: a module that goes back to a literal, or
    # a root build file that quietly defaults an absent environment, would
    # produce a perfectly good APK carrying an identity that nothing else in the
    # release agrees with - and AutoRootPolicy binds a qualification to
    # versionCode AND versionName, so that identity decides whether an
    # unattended root attempt may trust a previous run's evidence.
    version_wiring = {}
    module_srcs = {}
    for module in ("app", "installer"):
        path = os.path.join(ROOT, module, "build.gradle.kts")
        try:
            with open(path, encoding="utf-8") as f:
                module_srcs[module] = f.read()
        except OSError as ex:
            fail("cannot read %s/build.gradle.kts: %s" % (module, ex))
    for module, gradle in module_srcs.items():
        code = re.search(r"versionCode\s*=\s*(.+)", gradle)
        name = re.search(r"versionName\s*=\s*(.+)", gradle)
        if not code or not name:
            fail("%s/build.gradle.kts declares no versionCode/versionName" % module)
            continue
        for what, m, key in (("versionCode", code, "dfrVersionCode"),
                             ("versionName", name, "dfrVersionName")):
            expr = m.group(1).strip()
            if 'rootProject.extra["%s"]' % key not in expr:
                fail("%s/build.gradle.kts sets %s to %r instead of the shared "
                     "rootProject.extra[%r]; a literal here ships as the derived "
                     "version while identifying as something else"
                     % (module, what, expr, key))
        version_wiring[module] = "rootProject.extra"

    root_gradle_path = os.path.join(ROOT, "build.gradle.kts")
    try:
        with open(root_gradle_path, encoding="utf-8") as f:
            root_gradle = f.read()
    except OSError as ex:
        root_gradle = ""
        fail("cannot read build.gradle.kts: %s" % ex)
    for env in ("DFR_VERSION_NAME", "DFR_VERSION_CODE"):
        if 'System.getenv("%s")' % env not in root_gradle:
            fail("build.gradle.kts no longer reads %s; the modules read the "
                 "version from there and nowhere else" % env)
    for key in ("dfrVersionName", "dfrVersionCode"):
        if 'extra["%s"]' % key not in root_gradle:
            fail("build.gradle.kts no longer exports extra[%r] that both modules "
                 "read" % key)
    # Absence must refuse, not default. A fallback here is the whole drift back:
    # it would compile one version into an APK published under another.
    if root_gradle.count("require(") < 3 or "Refusing to invent one" not in root_gradle:
        fail("build.gradle.kts no longer refuses an absent/unusable "
             "DFR_VERSION_NAME/DFR_VERSION_CODE; a default would compile a "
             "version the release does not publish under")
    for defaulted in ('System.getenv("DFR_VERSION_NAME") ?: "0',
                      'System.getenv("DFR_VERSION_CODE") ?: "0',
                      "toIntOrNull() ?: 1"):
        if defaulted in root_gradle:
            fail("build.gradle.kts defaults the version (%r) instead of refusing"
                 % defaulted)
    version_wiring["root"] = "env DFR_VERSION_NAME/DFR_VERSION_CODE, refuses if absent"

    release_yml = os.path.join(ROOT, ".github", "workflows", "release.yml")
    try:
        with open(release_yml, encoding="utf-8") as f:
            release_src = f.read()
    except OSError as ex:
        release_src = ""
        fail("cannot read .github/workflows/release.yml: %s" % ex)
    for signal in ("tools/resolve_release_version.sh",
                   "DFR_VERSION_NAME=$VER",
                   "DFR_VERSION_CODE=$VERSION_CODE"):
        if signal not in release_src:
            fail("release.yml no longer %s; the build would refuse, or would "
                 "build a version this run did not resolve" % signal)
    # The injection is only fail-closed if something reads the identity back out
    # of the artifacts: a renamed variable or a module that stopped reading the
    # shared value fails no gate until an APK ships the wrong version.
    if "aapt2 dump badging" not in release_src.replace('"$AAPT2" dump badging',
                                                       "aapt2 dump badging"):
        fail("release.yml no longer reads versionCode/versionName back out of the "
             "built APKs; the injected identity would be unverified")
    if "carries $name ($code) but this run publishes" not in release_src:
        fail("release.yml reads the APK version back but no longer refuses on a "
             "mismatch")
    # The footgun itself: reading a version out of the tree is what created the
    # possibility of the tag and the APKs disagreeing.
    if re.search(r"versionName['\"]?\s+app/build\.gradle\.kts", release_src) or \
            "grep -m1 'versionName' app/build.gradle.kts" in release_src:
        fail("release.yml reads a versionName out of app/build.gradle.kts again; "
             "the version is derived per run and lives in no file")
    r["checks"]["version_wiring"] = version_wiring

    # --- Auto Root after full boot ----------------------------------------
    # Auto Root changes WHEN the chain runs, so every one of its refusals is a
    # gate. The policy is pure and host-tested (tools/tests/AutoRootPolicyTest.java);
    # what cannot be tested without Android is checked here by shape.
    autoroot = {}
    for signal in ('PHASE_STARTED = "STARTED"',
                   'PHASE_FAILED_LOCKED = "FAILED_LOCKED"',
                   "MAX_ATTEMPTS_PER_BOOT"):
        if signal not in autoroot_policy_src:
            fail("AutoRootPolicy no longer defines %r" % signal)
    for signal in ("Auto Root is not opted in",
                   "still in the boot that qualified Auto Root",
                   "switched on during this boot",
                   "boot window; a framework restart re-broadcasts it",
                   "time since kernel boot is unavailable",
                   "native execution already began in this boot",
                   "a stage marker is already present",
                   # the refusal is written across two source lines, so match the
                   # half that identifies it rather than the joined message
                   "refusing rather than assuming a clean boot"):
        if signal not in autoroot_policy_src:
            fail("AutoRootPolicy no longer refuses on %r" % signal)
    # A qualification must be bound to the bytes and the build it was observed
    # with, or "it worked once" would survive a repin.
    policy_code = code_only(autoroot_policy_src)
    for field in ("version_code", "version_name", "ksud_sha256",
                  "device_fingerprint", "boot_id", "opt_in_boot_id"):
        if field not in policy_code:
            fail("the Auto Root qualification no longer binds %r" % field)
    # A field the record merely CARRIES decides nothing. These two are the ones
    # that keep a framework restart and a stale qualification from running the
    # chain, so the comparison itself has to be there.
    # The comparison itself, not just the field name: `q.get("boot_id")` also
    # appears where withOptIn copies the record forward, so naming it proves
    # nothing about the refusal.
    for compared in ('in.currentBootId.equals(q.get("boot_id"))',
                     'in.currentBootId.equals(q.get("opt_in_boot_id"))'):
        if compared not in policy_code:
            fail("AutoRootPolicy no longer refuses on %s; the record would carry the "
                 "field without it gating anything" % compared)
    # The journal is the one-attempt-per-boot guarantee, so it has to survive the
    # event that makes a repeat dangerous: an abrupt reboot. rename(2) alone is
    # atomic for a reader, not durable.
    if "out.fd.sync()" not in autoroot_store_src or "fsyncDir(" not in autoroot_store_src:
        fail("AutoRootStore no longer fsyncs the record and its directory; a STARTED "
             "that does not survive a crash is not a guarantee")
    # The switch must be bound to the boot it was flipped in: BOOT_COMPLETED is
    # re-broadcast by a framework restart with an unchanged boot_id.
    if "DfrRootCoordinator.readBootId()" not in autoroot_store_src:
        fail("AutoRootStore sets the opt-in without recording the boot it happened "
             "in, so a framework restart could be taken for a full boot")
    # The records must NOT live in the app's private data directory.
    #
    # It is the textbook answer for state a boot-time component reads before the
    # user unlocks, and on this app it silently does not work: hosted in the
    # `system` process with sharedUserId=android.uid.system, the app has no usable
    # files dir - after a verified manual run both /data/data/<pkg>/ and
    # /data/user_de/0/<pkg>/ held only cache and code_cache, no files/ at all, and
    # nothing was logged. The qualification was never written and the checkbox
    # stayed disabled with no visible reason. /data/system is where this process
    # demonstrably can write (KsudStage stages the daemon there every run), is
    # available before unlock, and is not world-writable.
    store_code = code_only(autoroot_store_src)
    for banned in ("createDeviceProtectedStorageContext", "filesDir"):
        if banned in store_code:
            fail("AutoRootStore is back on the app's private data directory (%s); "
                 "this app has no usable files dir in the system process and the "
                 "failure is silent" % banned)
    for path in ("/data/system/dfreroot-autoroot-qualification",
                 "/data/system/dfreroot-autoroot-journal"):
        if path not in autoroot_store_src:
            fail("AutoRootStore no longer stores %s where this process can write it"
                 % path)
    # A write that fails must reach the operator, not only logcat.
    if "could not write" not in autoroot_store_src:
        fail("AutoRootStore no longer reports a failed qualification write to the "
             "caller; the silent version cost an operator hours")
    # The marker probe must be able to say "could not tell".
    coord_code = code_only(coord_src)
    if "AutoRootPolicy.MARKER_UNKNOWN" not in coord_code \
            or "OsConstants.ENOENT" not in coord_code:
        fail("the marker probe collapsed back to a boolean; a failed lookup would "
             "read as a clean device")
    if "KsudStage.pinnedKsudSha256()" not in autoroot_store_src:
        fail("AutoRootStore no longer binds the qualification to the pinned ksud "
             "digest, so a repinned daemon would keep an old qualification valid")
    if "qualifies(result.nativeResult, result.postRootComplete" not in autoroot_store_src:
        fail("AutoRootStore records a qualification without requiring a verified "
             "same-boot completion")
    # STARTED is the one-attempt-per-boot guarantee: it has to be written before
    # the destructive transaction, which is what beforeNativeRun() is for.
    if "beforeNativeRun" not in autoroot_service_src or \
            "PHASE_STARTED" not in autoroot_service_src:
        fail("DfrAutoRootService no longer records STARTED before the native run")
    if "AutoRootPolicy.evaluate(" not in autoroot_service_src:
        fail("DfrAutoRootService no longer consults the Auto Root policy")
    # The boot window must be measured locally at service entry, not read from
    # the caller's Intent and not resampled on each readiness poll.
    svc_code = code_only(autoroot_service_src)
    if "val serviceStartMs = monotonicNow()" not in svc_code \
            or "broadcastUptimeMs = serviceStartMs" not in svc_code \
            or "q.broadcastUptimeMs = broadcastUptimeMs" not in svc_code \
            or "SystemClock.elapsedRealtime()" not in svc_code \
            or "-1L" not in svc_code:
        fail("DfrAutoRootService must pass its own service-entry monotonic time "
             "to the boot-window policy; an Intent extra is telemetry only")
    # ...and the assertion above only proves the GOOD assignment is present. A
    # later line re-assigning the field from the Intent extra would leave it
    # passing while the boot window moved back under a caller's control, which
    # is the "gate enforced at one entry point" failure of AGENTS.md 3.2. So
    # enumerate every assignment and require each one to be the local sample or
    # the refusing initialiser; nothing else may reach the policy's clock.
    #
    # Constrain the RIGHT-hand side of every assignment whose target ends in
    # this name, qualified or not. An earlier version excluded qualified writes
    # with a lookbehind, so that "q.broadcastUptimeMs = broadcastUptimeMs" - the
    # policy input being filled FROM the field - would not be read as a write to
    # it. That also excluded "this.broadcastUptimeMs = receiverElapsedMs", which
    # is a perfectly valid Kotlin write to the field, carries no mention of the
    # extra for the next check to catch, and leaves the safe assignment in place
    # to satisfy the one above. Reported by Codex on PR #40 and upheld: a check
    # whose scope is decided by the spelling of the left-hand side is a check
    # that a qualifier defeats.
    #
    # So allow the field itself as a source - a copy out of it cannot corrupt it
    # - and nothing else but the local sample and the refusing initialiser.
    allowed_uptime_rhs = ("-1L", "serviceStartMs", "broadcastUptimeMs")
    for rhs in re.findall(r"[\w.]*\bbroadcastUptimeMs\s*=(?!=)\s*([^\n]+)",
                          svc_code):
        if rhs.strip() not in allowed_uptime_rhs:
            fail("DfrAutoRootService assigns broadcastUptimeMs from %r; the "
                 "boot window may only carry the service's own monotonic "
                 "sample, and an Intent extra is telemetry only"
                 % rhs.strip())
    # The extra is readable - it measures the receiver-to-service handoff - but
    # it must never be what the policy reads. Bind that to the field name, not
    # to the current variable spelling.
    for line in svc_code.splitlines():
        if "EXTRA_RECEIVER_UPTIME_MS" in line and "broadcastUptimeMs" in line:
            fail("DfrAutoRootService derives broadcastUptimeMs from the "
                 "receiver's Intent extra; a caller would then choose whether "
                 "the boot window had expired")
    if "in.broadcastUptimeMs > MAX_BOOT_WINDOW_MS" not in policy_code:
        fail("AutoRootPolicy no longer bounds how long after kernel boot a trigger "
             "may start an attempt; a framework restart hours into a session would "
             "be indistinguishable from a full boot")
    for forbidden in ("AlarmManager", "JobScheduler", "setRepeating", "setExactAndAllowWhileIdle"):
        if forbidden in autoroot_service_src or forbidden in boot_receiver_src:
            fail("the Auto Root path schedules work through %s; the retry budget "
                 "must stay bounded by MAX_ATTEMPTS_PER_BOOT and one thread"
                 % forbidden)
    if "ACTION_BOOT_COMPLETED" not in boot_receiver_src:
        fail("DfrBootReceiver no longer compares the broadcast action")
    receiver_code = code_only(boot_receiver_src)
    if "SystemClock.elapsedRealtime()" not in receiver_code \
            or "receiver monotonic clock unavailable" not in receiver_code \
            or "-1L" not in receiver_code:
        fail("DfrBootReceiver no longer maps a failed monotonic sample to -1 "
             "telemetry; an exception must not escape system_server")
    if "private fun monotonicNow(): Long = try" not in svc_code \
            or "monotonic clock unavailable" not in svc_code:
        fail("DfrAutoRootService no longer maps clock failures to the refusing "
             "-1 policy input")
    # The receiver must gate on the CLASSIFIED verdict and log it. A boolean here
    # is what made an observed refusal useless as evidence: one line stood for an
    # absent record, an unreadable one, a version bump, a changed ksud digest, a
    # firmware change and a deliberate opt-out alike, so step 7's acceptance run
    # could not tell which boundary it had just exercised. Kotlin needing an
    # Android runtime is why this is a static check (AGENTS.md section 5).
    if "AutoRootStore.optInVerdict()" not in boot_receiver_src \
            or "AutoRootPolicy.OPT_IN_OK" not in boot_receiver_src:
        fail("DfrBootReceiver no longer gates on the classified opt-in verdict; a "
             "bare boolean cannot say WHICH boundary refused, and the boot log is "
             "the only record an unattended acceptance run leaves behind")
    if "$verdict" not in boot_receiver_src:
        fail("DfrBootReceiver decides on the verdict but does not log it; a refusal "
             "nobody can read is the same as no refusal for acceptance purposes")
    if "not opted in for this build" in boot_receiver_src:
        fail("DfrBootReceiver is back to the collapsed refusal message, which reads "
             "as an opt-out for six different facts")
    # The ordering implication inside the policy: OPTED_OUT must mean the build
    # comparison PASSED, or an observed OPTED_OUT proves nothing about the opt-out
    # boundary. Host-tested four ways too; checked here because a reordering is a
    # one-line edit that no compiler complains about.
    verdict_fn = re.search(r"public static String optInVerdict\(.*?\n    \}",
                           autoroot_policy_src, re.S)
    if verdict_fn is None:
        fail("AutoRootPolicy.optInVerdict is gone; DfrBootReceiver's classified "
             "refusal has nothing behind it")
    else:
        body = verdict_fn.group(0)
        if "OPT_IN_BUILD_MISMATCH" not in body or "OPT_IN_OPTED_OUT" not in body:
            fail("AutoRootPolicy.optInVerdict no longer distinguishes a build "
                 "mismatch from a deliberate opt-out")
        elif body.index("OPT_IN_BUILD_MISMATCH") > body.index("OPT_IN_OPTED_OUT"):
            fail("AutoRootPolicy.optInVerdict checks the opt-in flag before the "
                 "build comparison, so OPTED_OUT no longer implies buildMatches "
                 "passed; an observed OPTED_OUT would stop being evidence that the "
                 "opt-out boundary was the one exercised")
    manifest_path = os.path.join(ROOT, "app", "src", "main", "AndroidManifest.xml")
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = f.read()
    except OSError as ex:
        fail("cannot read AndroidManifest.xml: %s" % ex)
        manifest = ""
    manifest_code = re.sub(r"<!--.*?-->", "", manifest, flags=re.S)
    svc = re.search(r"<service[^>]*DfrAutoRootService.*?/>", manifest_code, flags=re.S)
    if not svc:
        fail("DfrAutoRootService is not declared in the manifest")
    elif 'android:exported="false"' not in svc.group(0):
        fail("DfrAutoRootService is exported; an external component must not be "
             "able to ask for an unattended root run")
    else:
        autoroot["service_exported"] = "false"
    rcv = re.search(r"<receiver[^>]*DfrBootReceiver.*?</receiver>", manifest_code,
                    flags=re.S)
    if not rcv:
        fail("DfrBootReceiver is not declared in the manifest")
    else:
        if "android.intent.action.BOOT_COMPLETED" not in rcv.group(0):
            fail("DfrBootReceiver has no BOOT_COMPLETED filter, so Auto Root can "
                 "never start")
        # It receives a protected system broadcast, so it is exported on purpose -
        # but it must carry nothing else, and nothing may be launched from it
        # except the non-exported service.
        extra = [a for a in re.findall(r'<action android:name="([^"]+)"', rcv.group(0))
                 if a not in ("android.intent.action.BOOT_COMPLETED",
                              "android.intent.action.LOCKED_BOOT_COMPLETED")]
        if extra:
            fail("DfrBootReceiver listens to %s beyond the boot broadcasts" % extra)
        autoroot["boot_receiver_actions"] = "boot only"
    if "android.permission.RECEIVE_BOOT_COMPLETED" not in manifest_code:
        fail("RECEIVE_BOOT_COMPLETED is not requested, so the boot receiver would "
             "never fire")
    # --- the R1 correction: a pre-transaction failure does not spend the boot --
    # `nativeStarted` is set immediately before transaction 5 and every page-cache
    # write lives inside that call, so a failure with it false wrote provably
    # nothing: no marker, no patched artefact, no armed hook. Recording that as
    # FAILED_LOCKED spent the only automatic attempt on a refusal that changed
    # nothing - the shape that matters being the hop losing a race with a slow
    # network_stack at boot, on a device nobody is watching. It is recorded as
    # readiness instead, and the attempt count keeps the loop finite.
    service_code = code_only(autoroot_service_src)
    if "!result.nativeStarted -> AutoRootPolicy.PHASE_PREFLIGHT" not in service_code:
        fail("DfrAutoRootService no longer distinguishes a pre-transaction failure "
             "from one that wrote to the page cache; a refusal that changed nothing "
             "would spend the boot's only automatic attempt")
    if "else -> AutoRootPolicy.PHASE_FAILED_LOCKED" not in service_code:
        fail("DfrAutoRootService no longer locks the boot once transaction 5 has "
             "been issued; a hard reboot is the only recovery boundary there")
    if "DfrRootCoordinator.AUTOROOT_CONTROLLER_TIMEOUT_MS" not in service_code:
        fail("the unattended path no longer passes its own CONTROLLER deadline; a "
             "boot-time hop competes with dexopt and a button press does not")
    coord_all = code_only(coord_src)
    if "AUTOROOT_CONTROLLER_TIMEOUT_MS" not in coord_all:
        fail("DfrRootCoordinator no longer defines the unattended CONTROLLER deadline")

    # --- the verdict notification ------------------------------------------
    # The only channel an unattended boot-time run has to a human: this firmware's
    # default log buffer is 128 KiB per buffer and system_server saturates it in
    # seconds, so the [DFR][*] trace of a boot run is gone before anyone reads it.
    notifier_code = code_only(notifier_src)
    if "notif_root_failed_detail" not in notifier_code \
            or "R.string.notif_root_failed)" not in notifier_code:
        fail("RootNotifier no longer reports a FAILED run with its own title and "
             "reason; an unattended path that fails silently leaves the owner "
             "believing the phone re-roots itself")
    if "if (result.success) {" not in notifier_code or "} else {" not in notifier_code:
        fail("RootNotifier no longer branches on the run's verdict, so success and "
             "failure would read the same")
    if "FAILED to post" not in notifier_src:
        fail("RootNotifier no longer logs a failed post; a missing notification "
             "permission would become invisible")
    for caller, src in (("DfrAutoRootService", autoroot_service_src),
                        ("MainActivity", dfr_source("MainActivity.kt"))):
        if "RootNotifier.notifyRunVerdict" not in code_only(src):
            fail("%s no longer posts the run verdict" % caller)
    if "android.permission.POST_NOTIFICATIONS" not in manifest:
        fail("POST_NOTIFICATIONS is not requested, so the verdict notification "
             "would never be posted on this SDK level")

    # --- Apply Modules (Soft Reboot) ---------------------------------------
    # The operation is legitimate and its mechanism is established by reading the
    # pinned KernelSU revision's own source: soft_reboot() daemonises into PID 1's
    # mount namespace, then stop -> on_post_data_fs() -> start -> on_services() ->
    # on_boot_completed(). The kernel is never restarted. What must stay true here
    # is that it can never become a way to run the exploit again, and that it is
    # never offered to a boot this build did not verifiably root.
    soft_policy_code = code_only(soft_reboot_policy_src)
    soft_receiver_code = code_only(soft_reboot_receiver_src)
    # STRUCTURAL: no path from the notification action to the chain.
    for banned in ("DfrRootCoordinator.run", "DirtyFrag", "StageHop",
                   "KsudStage.stageFromAssets"):
        if banned in soft_receiver_code:
            fail("DfrSoftRebootReceiver references %r; the soft-reboot action must "
                 "never be able to run the chain - it may only ask an already-rooted "
                 "boot to re-apply modules" % banned)
    if "PostRootStatus.evaluate" not in soft_policy_code \
            or "if (!verdict.complete) {" not in soft_policy_code:
        fail("SoftRebootPolicy no longer refuses on an absent or stale same-boot "
             "post-root state; a second, looser notion of 'rooted' is how the two "
             "drift apart")
    for signal in ("requestBootId.equals(in.currentBootId)",
                   "pinned.equals(actual)",
                   "PHASE_CLAIMED"):
        if signal not in soft_policy_code:
            fail("SoftRebootPolicy no longer enforces %r" % signal)
    # The binary is chosen by digest, never by path: /data/adb/ksud was observed
    # holding the root manager's own build rather than the pinned daemon.
    if "pinnedKsudSha256" not in soft_policy_code:
        fail("SoftRebootPolicy no longer compares the candidate ksud against the "
             "pinned digest; it would hand a privileged lifecycle operation to an "
             "unidentified binary")
    # The digest gate must stay reachable, but the root transport must not depend
    # on /system/bin/su. The target proved that path exists in Termux's KernelSU
    # namespace and is absent from system_server's mount namespace. Nor may the
    # shared platform uid be granted in the manager. The DFR-specific pair instead
    # stages the exact pinned helper and invokes its debug-su ioctl path; the paired
    # kernel module restricts that ioctl to a helper and real parent carrying the
    # policy-owned system_server SID; the helper task name is defense in depth.
    transport_code = code_only(dfr_source("RootTransport.kt"))
    su_core_path = os.path.join(JNI_DIR, "dfr_su_core.c")
    su_jni_path = os.path.join(JNI_DIR, "dfr_su_jni.c")
    verified_exec_path = os.path.join(JNI_DIR, "dfr_verified_exec_core.c")
    sources = {}
    for label, path in (("dfr_su_core.c", su_core_path),
                        ("dfr_su_jni.c", su_jni_path),
                        ("dfr_verified_exec_core.c", verified_exec_path)):
        try:
            with open(path, encoding="utf-8") as f:
                sources[label] = code_only(f.read())
        except OSError as ex:
            fail("cannot read %s: %s" % (label, ex))
            sources[label] = ""
    su_core_code = sources["dfr_su_core.c"]
    su_jni_code = sources["dfr_su_jni.c"]
    verified_exec_code = sources["dfr_verified_exec_core.c"]

    if "fun sha256AsRoot(path: String): String? {" not in transport_code \
            or "sha256sum '" not in transport_code \
            or 'val prefix = "DFR_SHA256="' not in transport_code:
        fail("RootTransport no longer takes the candidate digest through the root "
             "shell; the installed daemon is under /data/adb, which uid 1000 cannot "
             "traverse")
    for signal in ('KsudStage.stageFromAssets(context)',
                   'stageLog.contains("KSUD_STAGED_VERIFY=PASS")',
                   'actual != KsudStage.pinnedKsudSha256()',
                   'System.loadLibrary("dfrsu")',
                   'nativeExecPinnedDaemon(',
                   'transport=dfr-fork-grant'):
        if signal not in transport_code:
            fail("RootTransport no longer carries the DFR transport invariant %r"
                 % signal)

    # The refuted shape, by mechanism rather than by spelling. system_server
    # cannot execve a file under /data - proven for apk_data_file and
    # system_data_file - so a transport that starts a process from a pathname
    # the app controls is the failure this rewrite exists to remove.
    if "ProcessBuilder" in transport_code:
        fail("RootTransport is starting a process from the app's own domain "
             "again; u:r:system_server:s0 cannot execve anything under /data, "
             "which is what refuted the previous transport")
    if "libdfr_verified_exec.so" in transport_code:
        fail("RootTransport still names the retired standalone launcher; it is "
             "not packaged, because the device refuses to execute it")
    if "SU_CANDIDATES" in transport_code or '"/system/bin/su"' in transport_code:
        fail("RootTransport fell back to namespace-dependent su probing; ZZIC "
             "proved that system_server cannot resolve those paths")

    # The grant must precede the exec, and every step of it must be nameable.
    # A transport that reports one undifferentiated failure tells the next
    # physical run nothing about which boundary refused (AGENTS.md 3.7).
    # The driver-fd supercall, and the gate that is now the only thing standing
    # between it and the panic it caused.
    #
    # This used to assert the call's ABSENCE by mechanism. The panic record
    # retired that reasoning: the supercall worked - the fd was installed for
    # this transport's own forked child - and the kernel died 152 us later in
    # the paired module's predicate, on a put_cred() that
    # CONFIG_KSU_SAMSUNG_KDP refuses. Asking a BROKEN module for the grant is
    # what breaks the device, so AGENTS.md 3.6.1 states the owner's decision as
    # a condition, and this guard proves the condition instead of the absence.
    #
    # Four properties, because the call is one edit away from being unguarded
    # if any one of them lapses:
    #   1. exactly one shipped source may name the supercall at all;
    #   2. transport_fix_allowed is checked before driver-fd acquisition AND
    #      grant_root, so an inherited fd cannot bypass the marker;
    #   3. the flag is threaded, not decided below the caller;
    #   4. the caller derives it from PostRootStatus.transportFixAllowed() on a
    #      verdict for the current boot.
    SUPERCALL_TOKENS = ("__NR_reboot", "SYS_reboot", "0xdeadbeef", "0xcafebabe")
    SUPERCALL_OWNER = "dfr_su_core.c"
    shipped = []
    for name in sorted(os.listdir(JNI_DIR)):
        if name.endswith((".c", ".h", ".S", ".inc")):
            shipped.append(os.path.join(JNI_DIR, name))
    for name in sorted(os.listdir(DFR_JAVA_DIR)):
        if name.endswith((".kt", ".java")):
            shipped.append(os.path.join(DFR_JAVA_DIR, name))
    supercall_owner_code = None
    supercall_header_code = None
    for path in shipped:
        try:
            with open(path, encoding="utf-8") as f:
                code = code_only(f.read())
        except OSError as ex:
            fail("cannot read %s: %s" % (path, ex))
            continue
        base = os.path.basename(path)
        if base == SUPERCALL_OWNER:
            supercall_owner_code = code
            continue
        if base == "dfr_su_core.h":
            supercall_header_code = code
        for forbidden in SUPERCALL_TOKENS:
            if forbidden in code:
                fail("%s names %r: the driver-fd supercall is gated in %s and "
                     "nowhere else, because a gate enforced in one file is a "
                     "gate a second file defeats (AGENTS.md 3.6.1)"
                     % (base, forbidden, SUPERCALL_OWNER))

    if supercall_owner_code is None:
        fail("%s is missing; the supercall gate has no owner to prove"
             % SUPERCALL_OWNER)
    else:
        header = supercall_header_code or ""
        if "int (*driver_fd)(int *fd_out, struct dfr_su_transport_diag *diag);" \
                not in header:
            fail("struct dfr_su_ops.driver_fd lost the independently reported "
                 "transport diagnostics")
        if "DFR_SU_STEP_TRANSPORT_FIX_GATED" not in header:
            fail("DFR_SU_STEP_TRANSPORT_FIX_GATED is gone; marker refusal would "
                 "be indistinguishable from driver acquisition failure")

        # The call site itself. Everything from the refusing branch to the
        # syscall must be one unbroken sequence, so the name can only be
        # reached with the flag set.
        gate = supercall_owner_code.find("if (!transport_fix_allowed) {")
        call = supercall_owner_code.find("syscall(__NR_reboot")
        acquire = supercall_owner_code.find("int dfr_acquire_driver_fd(")
        driver = supercall_owner_code.find("ops->driver_fd(&driver_fd, &diag)")
        grant = supercall_owner_code.find("ops->grant_root(driver_fd)")
        if min(gate, call, acquire, driver, grant) < 0 or not (gate < driver < grant):
            fail("%s no longer gates the complete driver-fd/grant path; an "
                 "inherited [ksu_driver] fd must not bypass transport_fix"
                 % SUPERCALL_OWNER)
        if supercall_owner_code.count("syscall(__NR_reboot") != 1:
            fail("%s names the supercall more than once; only the gated call "
                 "site may exist" % SUPERCALL_OWNER)
        # The scan AFTER the call must be unconditional on the call's return.
        # reboot_handler_pre() is a pre-handler: it queues the fd install and
        # lets the real sys_reboot run, so a failing syscall does not mean no
        # fd was installed. Returning early on rc != 0 collapses "filtered
        # before the handler" and "fd installed, then the syscall failed" into
        # one token (AGENTS.md 3.7) and points the next physical run at the
        # wrong question. This path cannot be reached from a host test - the
        # syscall is real - so it is asserted statically (AGENTS.md 5).
        if acquire >= 0:
            acquire_end = supercall_owner_code.find(
                "static const struct dfr_driver_fd_ops", acquire)
            acquire_code = supercall_owner_code[acquire:acquire_end]
            call_in_acquire = acquire_code.find("rc = ops->supercall(&fd)")
            rescan = acquire_code.find("if (ops->scan(fd_out) == 0)",
                                       call_in_acquire)
            if call_in_acquire < 0 or rescan < 0:
                fail("%s does not re-scan /proc/self/fd after the supercall; "
                     "a returned success is not evidence the fd exists "
                     "(AGENTS.md 3.5)" % SUPERCALL_OWNER)
            elif "return -1;" in acquire_code[call_in_acquire:rescan]:
                fail("%s returns before re-scanning when the supercall fails. "
                     "The install is queued as task_work and the real syscall "
                     "runs after the handler, so its failure does not mean no "
                     "fd was installed - observe first, decide after "
                     "(AGENTS.md 3.7)" % SUPERCALL_OWNER)
        # Nothing in the native layer may synthesise the flag.
        for bad in ("transport_fix_allowed = 1", "transport_fix_allowed = true",
                    "transport_fix_allowed || ", "|| transport_fix_allowed"):
            if bad in supercall_owner_code:
                fail("%s derives transport_fix_allowed (%r) instead of taking it "
                     "as a parameter; the evidence lives in a record this "
                     "layer cannot read (AGENTS.md 3.6.1)"
                     % (SUPERCALL_OWNER, bad))

    # The caller, which is the only layer that can read the marker. Kotlin that
    # needs an Android runtime cannot be unit-tested here, so the invoked shape
    # is asserted statically (AGENTS.md 5).
    transport_kt_code = code_only(dfr_source("RootTransport.kt"))
    if "fun prepare(context: Context, transportFixAllowed: Boolean)" not in \
            transport_kt_code:
        fail("RootTransport.prepare no longer takes transportFixAllowed; a "
             "default here would be a decision taken without the evidence "
             "AGENTS.md 3.6.1 requires")
    derives_gate = "PostRootStatus.transportFixAllowed(" in soft_receiver_code
    if not derives_gate:
        fail("DfrSoftRebootReceiver no longer derives the supercall gate from "
             "PostRootStatus.transportFixAllowed(); the grant path must "
             "not be issued on any weaker evidence (AGENTS.md 3.6.1)")
    if "RootTransport.prepare(context, transportFixAllowed)" not in \
            soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer passes the derived gate into the "
             "transport")

    # A breadcrumb written before a privileged step is worthless if failing to
    # write it lets the step happen anyway.
    if "private fun refuseWithoutTrace(" not in soft_receiver_code \
            or "AutoRootStore.traceSoftReboot(bootId, phase) ?: return false" \
            not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer refuses when the pre-operation "
             "trace cannot be persisted; that rebuilds the undiagnosable "
             "teardown the trace exists to prevent")
    for signal in ('DFR_KSU_DRIVER_LINK "[ksu_driver]"',
                   '__NR_getdents64',
                   'DFR_KSU_IOCTL_GRANT_ROOT 0x4b01u',
                   'uid = ops->current_uid()',
                   'if (uid != 0)',
                   'DFR_SU_STEP_NOT_ROOT',
                   'dfr_verified_execveat(argv[0], pinned_hex'):
        if signal not in su_core_code:
            fail("the native transport no longer carries the grant-before-exec "
                 "invariant %r" % signal)
    # The whole sequence, not just one pair. The grant must come before the
    # credential is checked, before the namespace switch that needs it, and
    # before either exec - and the check must come before the execs too, because
    # a returned success is not evidence of root (AGENTS.md 3.5).
    order = ("ops->fd_quarantine(&fdq_method)",
             "if (!transport_fix_allowed)",
             "ops->driver_fd(&driver_fd, &diag)",
             "ops->grant_root(driver_fd)",
             "uid = ops->current_uid()", "if (uid != 0)",
             "ops->enter_init_mnt_ns()",
             "dfr_verified_execveat(argv[0], pinned_hex", "execv(argv[0], argv)")
    positions = [su_core_code.find(signal) for signal in order]
    if any(at < 0 for at in positions):
        fail("the native transport lost a step of the grant-before-exec "
             "sequence: %r" % [s for s, at in zip(order, positions) if at < 0])
    elif positions != sorted(positions):
        fail("the native transport performs the grant-before-exec sequence out "
             "of order; obtaining root after an exec is the shape the device "
             "refused, and executing before the uid check trusts a boolean")

    # The descriptor boundary of the fork/exec, asserted the same way the
    # supercall gate is: by ownership and by position.
    #
    # The child is a forked copy of system_server, so it starts with
    # system_server's whole descriptor table - Binder, the HALs, the logging
    # sockets, the control socket to lmkd. Anything its owner did not mark
    # FD_CLOEXEC crosses the exec and outlives the generation of system_server
    # that opened it. On this device the lmkd endpoint of the system_server a
    # soft reboot destroyed (inode 47482) was still held as fd 148 by this
    # transport's descendants, and later that boot lmkd's main thread stopped
    # progressing in sock_alloc_send_pskb and took the framework down with it.
    #
    # The leak is proven; its role in the stall is not, and this guard does not
    # assume one. It asserts the hermetic property instead, which is the only
    # form a fail-closed boundary can take here: no descriptor crosses the exec
    # unless dfr_su_core.c names it. Naming lmkd's socket specifically would be
    # the same defect in a smaller costume.
    #
    # Four properties, mirroring the supercall gate, because any one of them
    # lapsing makes the exec porous again:
    #   1. the quarantine is the FIRST thing after stdio, so no path between
    #      fork and exec - present or future - can reach an exec without it;
    #   2. its failure is its own refusal step, never a logged inconvenience;
    #   3. exactly one shipped source forks and execs at all, so there is no
    #      second fork/exec that could skip the call (AGENTS.md 3.2);
    #   4. the transport's own pipes are O_CLOEXEC at creation, so they do not
    #      leak through anything ELSE inside system_server that forks.
    if "int dfr_fd_quarantine(int *method_out)" not in su_core_code:
        fail("dfr_fd_quarantine is gone; the fork/exec would hand "
             "system_server's descriptor table to the daemon it starts")
    # The entry classifier's three outcomes. Two would mean a numeric name the
    # code cannot represent is reported exactly as "." is, which is how the first
    # version of this change walked past a descriptor while reporting the sweep a
    # success (found in review on PR #47). Only the non-numeric outcome may be
    # skipped, and the walk must REFUSE on the other one - a host cannot create a
    # descriptor named above INT_MAX, so this is not reachable from a test.
    if "DFR_FD_NAME_UNREPRESENTABLE" not in su_core_code \
            or "DFR_FD_NAME_NOT_NUMERIC" not in su_core_code:
        fail("the descriptor-name classifier collapsed its outcomes; a numeric "
             "name this code cannot represent must not be reported the same way "
             "as '.', or the quarantine skips a real descriptor and still "
             "reports success")
    if "65535" in su_core_code:
        fail("a descriptor-number cap is back in the transport. RLIMIT_NOFILE is "
             "system_server's, not this file's to assume, and a capped name was "
             "indistinguishable from '.' to the quarantine")
    scan_at = su_core_code.find("int dfr_fd_quarantine_proc_scan(void)")
    if scan_at < 0:
        fail("the /proc/self/fd fallback is gone or no longer separable; on a "
             "kernel with CLOSE_RANGE_CLOEXEC it is unreachable from a test "
             "unless it is its own function")
    else:
        scan_end = su_core_code.find("int dfr_fd_quarantine(int *method_out)",
                                     scan_at)
        scan_code = su_core_code[scan_at:scan_end]
        unrep = scan_code.find("parsed == DFR_FD_NAME_UNREPRESENTABLE")
        if unrep < 0 or "return -1;" not in scan_code[unrep:unrep + 400]:
            fail("the /proc walk no longer refuses a descriptor name it cannot "
                 "represent; skipping one leaves it unmarked while the sweep "
                 "reports PROC_SCAN success (AGENTS.md 2)")
    if "CLOSE_RANGE_CLOEXEC" not in su_core_code:
        fail("the descriptor quarantine no longer marks the table close-on-exec; "
             "closing descriptors here instead would break the grant, and "
             "skipping them is the leak it exists to remove")
    child_main_at = su_core_code.find("static void child_main(")
    if child_main_at < 0:
        fail("child_main is gone; the pre-exec sequence has no owner to prove")
    else:
        quarantine_at = su_core_code.find("ops->fd_quarantine(&fdq_method)",
                                          child_main_at)
        comm_at = su_core_code.find("ops->set_comm(comm)", child_main_at)
        if quarantine_at < 0 or comm_at < 0 or quarantine_at > comm_at:
            fail("the descriptor quarantine is no longer the first thing the "
                 "child does after stdio; a refusal path or a future step "
                 "placed before it could reach an exec with system_server's "
                 "descriptor table behind it")
    # The single deliberate exception, and the fact that it IS deliberate: the
    # flag is cleared after the quarantine rather than the descriptor being left
    # out of it, so a reader finds the exception written down.
    keep_at = su_core_code.find("fcntl(driver_fd, F_SETFD, 0)")
    driver_at = su_core_code.find("ops->driver_fd(&driver_fd, &diag)")
    grant_at = su_core_code.find("ops->grant_root(driver_fd)")
    if keep_at < 0:
        fail("the KernelSU driver descriptor is no longer kept across the exec. "
             "Without it the pinned daemon's own init_driver_fd finds nothing "
             "and issues the supercall itself, from outside the gate of "
             "AGENTS.md 3.6.1 that stands in front of ours")
    elif not (driver_at < keep_at < grant_at):
        fail("the driver-descriptor exception is not applied between "
             "acquisition and the grant; an exception that is not where the "
             "quarantine can be seen to permit it is an oversight")
    if su_core_code.count("fcntl(driver_fd, F_SETFD, 0)") != 1:
        fail("more than one descriptor is exempted from the quarantine by hand; "
             "exactly one exception exists and it is the driver descriptor")
    if re.search(r"(?<![a-z_])pipe\(", su_core_code):
        fail("the native transport creates a pipe without O_CLOEXEC again; a "
             "write end inherited by any other fork inside system_server stays "
             "open after this child is gone")
    if "pipe2(out_pipe, O_CLOEXEC)" not in su_core_code \
            or "pipe2(status_pipe, O_CLOEXEC)" not in su_core_code:
        fail("the native transport's own channels are no longer O_CLOEXEC at "
             "creation")
    # Property 3: the transport forks in exactly one place, so there is no
    # second fork/exec that could skip the quarantine (AGENTS.md 3.2, which is
    # where this failure mode lives - a boundary enforced in one entry point is
    # a boundary the other entry point defeats).
    #
    # Scope is the transport, not the whole tree. exp.c also forks, but it does
    # so inside com.android.networkstack.process as part of the Dirty Frag
    # chain: a different parent, a different descriptor table, and not what the
    # device's leak came out of. Widening this guard to cover it would be a
    # claim about a process this change has not looked at.
    if "fork()" not in su_core_code:
        fail("dfr_su_core.c no longer forks; the transport's single spawn point "
             "is what makes the descriptor quarantine unbypassable")
    if su_core_code.count("fork()") != 1:
        fail("dfr_su_core.c forks in more than one place; each fork is another "
             "exec the quarantine can be forgotten in front of (AGENTS.md 3.2)")
    for token in ("fork(", "vfork(", "posix_spawn", "execv", "execl", "execve"):
        if token in su_jni_code:
            fail("dfr_su_jni.c names %r: the JNI layer marshals and nothing "
                 "else, so the forking child stays the one in dfr_su_core.c "
                 "that quarantines its descriptors first" % token)
    # And no NEW Kotlin source may start a process. Every component of this app
    # runs at android:process="system", so a process started from Kotlin is a
    # fork of system_server with whatever descriptor hygiene the platform's own
    # exec machinery happens to do - which this change did not read and
    # therefore does not vouch for either way.
    #
    # TerminalActivity is the one pre-existing site and is listed, not excused:
    # it is a developer terminal, not exported, reached only from MainActivity,
    # and its Runtime.exec() goes through ART rather than through this file's
    # transport. Whether libcore's child closes inherited descriptors is an
    # open question recorded in docs/HANDOFF.md, not a fact asserted here. The
    # allowlist exists so the count cannot grow while that is unanswered.
    PROCESS_START_TOKENS = ("ProcessBuilder", "Runtime.getRuntime().exec")
    KNOWN_PROCESS_STARTERS = {"TerminalActivity.kt"}
    for name in sorted(os.listdir(DFR_JAVA_DIR)):
        if not name.endswith((".kt", ".java")) or name in KNOWN_PROCESS_STARTERS:
            continue
        try:
            with open(os.path.join(DFR_JAVA_DIR, name), encoding="utf-8") as f:
                code = code_only(f.read())
        except OSError as ex:
            fail("cannot read %s: %s" % (name, ex))
            continue
        for token in PROCESS_START_TOKENS:
            if token in code:
                fail("%s starts a process from the app's own domain (%r). "
                     "Besides the SELinux refusal that retired that shape, it "
                     "is a fork of system_server with no descriptor quarantine "
                     "in front of it; the transport in dfr_su_core.c is the one "
                     "place this app starts a process" % (name, token))
    for name in sorted(KNOWN_PROCESS_STARTERS):
        try:
            with open(os.path.join(DFR_JAVA_DIR, name), encoding="utf-8") as f:
                code = code_only(f.read())
        except OSError as ex:
            fail("cannot read %s: %s" % (name, ex))
            continue
        if not any(token in code for token in PROCESS_START_TOKENS):
            fail("%s no longer starts a process; remove it from "
                 "KNOWN_PROCESS_STARTERS so the allowlist keeps naming only "
                 "what is actually there" % name)
    try:
        with open(os.path.join(JNI_DIR, "dfr_su_core.h"), encoding="utf-8") as f:
            su_header_code = code_only(f.read())
    except OSError as ex:
        fail("cannot read dfr_su_core.h: %s" % ex)
        su_header_code = ""
    for step in ("DFR_SU_STEP_FD_QUARANTINE",
                 "DFR_SU_STEP_DRIVER_FD", "DFR_SU_STEP_GRANT",
                 "DFR_SU_STEP_NOT_ROOT", "DFR_SU_STEP_MNT_NS",
                 "DFR_SU_STEP_DIGEST", "DFR_SU_STEP_TIMEOUT"):
        if step not in su_header_code or step not in su_core_code:
            fail("refusal step %s is declared but never reported; a step that "
                 "cannot be observed is not a diagnostic" % step)
    # Kotlin that needs an Android runtime cannot be unit-tested here, so the
    # JNI file's thinness is asserted statically (AGENTS.md 5).
    for signal in ('dfr_su_spawn(&dfr_su_real_ops', 'DFR_SU_SHELL "/system/bin/sh"'):
        if signal not in su_jni_code:
            fail("the JNI transport no longer routes through the tested core: "
                 "missing %r" % signal)
    if "ksu_is_allow_uid" in su_core_code or "1000" in su_jni_code:
        fail("the transport must not reason about uid 1000 itself; the paired "
             "module owns that predicate and a manager grant for the shared "
             "platform uid is not an acceptable remedy")

    for signal in ('dfr_sha256_fd_hex(fd, actual)',
                   '__NR_execveat, fd',
                   'AT_EMPTY_PATH'):
        if signal not in verified_exec_code:
            fail("verified exec no longer binds the digest to the file "
                 "description passed to execveat: missing %r" % signal)
    if verified_exec_code.count("open(path, O_RDONLY | O_CLOEXEC)") != 1:
        fail("verified exec must open the mutable pathname exactly once")
    if "RC_DIGEST_CHANGED" not in transport_code:
        fail("RootTransport no longer maps the bound-digest refusal to a "
             "distinct outcome")
    if "token.length != 64" not in transport_code:
        fail("RootTransport no longer validates the sha256sum output; anything that "
             "is not exactly one 64-character digest must read as 'could not tell'")
    if "transport.sha256AsRoot(path)" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer hashes the candidates through root")
    if "sha256File" in soft_receiver_code:
        fail("DfrSoftRebootReceiver hashes a candidate from this process again; every "
             "candidate is unreadable to uid 1000 after a successful run")
    # Order is load-bearing: the cheap boot-scope and post-root refusals run BEFORE a
    # root shell is requested, so a notification minted in another boot cannot make
    # the device prompt for root just to be refused.
    if "SoftRebootPolicy.precheck(inputs)" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer runs the unprivileged precheck first; a "
             "stale notification would ask for a root shell before being refused")
    if "RootTransport.prepare(context, transportFixAllowed)" not in \
            soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer prepares the pinned transport")
    elif soft_receiver_code.index("SoftRebootPolicy.precheck(inputs)") > \
            soft_receiver_code.index("RootTransport.prepare(context, transportFixAllowed)"):
        fail("DfrSoftRebootReceiver asks for a root shell before the unprivileged "
             "precheck has had a chance to refuse")
    # The gate must be derived BEFORE the transport is built with it. Deriving
    # it afterwards would mean a Prepared carrying a value nothing computed.
    # Guarded on derives_gate: a missing derivation is already reported above,
    # and indexing for it here would raise instead of producing a verdict - an
    # audit that crashes is an audit that gates nothing.
    elif derives_gate and \
            soft_receiver_code.index("PostRootStatus.transportFixAllowed(") > \
            soft_receiver_code.index(
                "RootTransport.prepare(context, transportFixAllowed)"):
        fail("DfrSoftRebootReceiver builds the transport before deriving the "
             "supercall gate")
    # Keep transport creation, helper identity drift and a started-but-unprivileged
    # helper as separate facts (AGENTS.md 3.7).
    if "NO_ROOT_TRANSPORT" not in soft_receiver_code \
            or "DIGEST_CHANGED at" not in soft_receiver_code \
            or "NOT_ROOT rc=" not in soft_receiver_code \
            or 'probe.output.contains("uid=0")' not in soft_receiver_code:
        fail("DfrSoftRebootReceiver collapses transport absence, daemon identity "
             "drift or a refused grant into one outcome")
    if "KernelSU Manager grant for uid" not in soft_receiver_code \
            or "1000 is neither required nor" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver again recommends a broad KernelSU grant for the "
             "shared platform uid")
    transport_source = dfr_source("RootTransport.kt")
    for claim in ("policy-owned", "`u:r:system_server:s0` SID",
                  "defense-in-depth check rather than", "as authority"):
        if claim not in transport_source:
            fail("RootTransport no longer documents the immutable SELinux identity "
                 "boundary: missing %r" % claim)
    # SoftRebootPolicy keeps both entry points: precheck for what needs no privilege,
    # evaluate for the full decision including the digest.
    if "public static Decision precheck(" not in soft_policy_code \
            or "private static Decision preCandidateChecks(" not in soft_policy_code:
        fail("SoftRebootPolicy no longer exposes the unprivileged precheck separately "
             "from the full evaluation")
    if "claimSoftReboot" not in soft_receiver_code or \
            "AutoRootStore.claimSoftReboot(bootId)" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer claims the boot before invoking ksud; "
             "a second tap would tear userspace down during the first teardown")
    # The persistent lock is a durable RECORD, not a mutex: two taps give two threads
    # that can both clear the policy before either has written it. The in-process
    # compare-and-set is what serialises them; the exclusive on-disk create covers
    # the other case the record is for, a process restarted within the same boot.
    # Neither alone closes the race the lock exists for.
    if "val lease = dispatchGuard.tryAcquire()" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer serialises concurrent taps in-process; "
             "two threads could both pass the policy and both dispatch a teardown")
    claim_at = soft_receiver_code.find("AutoRootStore.claimSoftReboot(bootId)")
    durable_at = soft_receiver_code.find("lease.markDurableClaimed()")
    close_at = soft_receiver_code.find("lease.close()")
    if min(claim_at, durable_at, close_at) < 0 or not (claim_at < durable_at < close_at):
        fail("DfrSoftRebootReceiver no longer releases its lease only before the "
             "durable claim boundary")
    store_claim = code_only(autoroot_store_src)
    if "var claimed = target.createNewFile()" not in store_claim \
            or "claimed = target.delete() && target.createNewFile()" not in store_claim \
            or store_claim.count("if (!claimed) {") != 2 \
            or 'return "could not take the soft-reboot lock exclusively"' \
                not in store_claim:
        fail("AutoRootStore no longer claims the soft-reboot lock exclusively through "
             "createNewFile() (O_CREAT|O_EXCL); a staged-then-renamed write is not a "
             "compare-and-set, so two concurrent claims would both succeed")
    # A timeout is an UNKNOWN and must not be reported as a handover (AGENTS.md 3.7):
    # a shell that hangs before reaching ksud produces the same timeout as one that
    # daemonised, and nothing here can tell them apart.
    if "outcome.rc == RootTransport.RC_TIMEOUT ->" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer gives a transport timeout its own "
             "outcome; merging it with a zero exit reports an uncertainty as a "
             "dispatch")
    if "notif_soft_reboot_undetermined" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer reports an undetermined soft reboot "
             "distinctly from a dispatched one")
    # A dispatch that may take userspace down with it must leave a durable trail
    # BEFORE it does. The build that rebooted this device was diagnosable only by
    # an absence; reasoning from an absence works once.
    for phase in ('"PREPARE"', '"PROBE_ENTER"', '"EXEC_ENTER path='):
        if "refuseWithoutTrace(context, bootId, %s" % phase not in soft_receiver_code:
            fail("DfrSoftRebootReceiver no longer records phase %s before acting; "
                 "a teardown would again leave nothing to read" % phase)
    probe_trace = soft_receiver_code.find(
        'refuseWithoutTrace(context, bootId, "PROBE_ENTER")')
    probe_call = soft_receiver_code.find('transport.runAsRoot("id"')
    if probe_trace < 0 or probe_call < 0 or probe_trace > probe_call:
        fail("the soft-reboot trace is written after the first privileged call; "
             "it exists to survive that call, so it must precede it")

    # The digest must be bound to the bytes that run, in the call that runs them.
    # Hashing a path and then executing that path binds the claim to a NAME, not to
    # bytes (AGENTS.md 3.5.1), and /data/adb/ksud is documented to change: it has
    # held the root manager's build and the pinned daemon at different times on this
    # device. Between the candidate hash and the call there is another hash, a policy
    # evaluation and a lock write with an fsync.
    for signal in ('transport.execPinnedDaemon(',
                   '"soft-reboot"',
                   "RootTransport.RC_DIGEST_CHANGED"):
        if signal not in soft_receiver_code:
            fail("DfrSoftRebootReceiver no longer execs ksud through the transport "
                 "that hashes the descriptor it launches (%s missing); a pathname "
                 "can change between the check and the call" % signal)
    if "outcome.rc == RootTransport.RC_DIGEST_CHANGED ->" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer reports a daemon whose bytes are not "
             "the pinned ones as its own outcome")
    # A shell between the decision and the exec would reopen the pathname, which is
    # the window the descriptor-bound exec exists to close.
    if "sha256sum" in soft_receiver_code and "exec \\\"" in soft_receiver_code:
        fail("DfrSoftRebootReceiver went back to hashing and exec'ing a pathname in "
             "a shell; that is two lookups of a mutable name")
    # Exit status 0 is ambiguous by construction: soft_reboot() returns Ok(()) when
    # ensure_uapi_version_matched() fails, and daemonises on the success path.
    if "exits 0 both when it daemonises" not in soft_reboot_receiver_src:
        fail("DfrSoftRebootReceiver no longer records that a ksud exit status of 0 "
             "is not evidence the soft reboot happened - it exits 0 both on the "
             "daemonising path and when it skips the operation on a UAPI mismatch")
    if "/data/system/dfreroot-softreboot-lock" not in autoroot_store_src:
        fail("AutoRootStore no longer keeps the per-boot soft-reboot lock")
    if 'PHASE_CLAIMED = "CLAIMED"' not in soft_policy_code \
            or "claimed_at_ms" not in soft_policy_code \
            or "PHASE_DISPATCHED" in soft_policy_code:
        fail("the soft-reboot lock must say CLAIMED/SPENT, not imply that ksud "
             "already received the command")
    for signal in ("FD_SOURCE=", "SUPERCALL_RC=", "SUPERCALL_ERRNO=",
                   "GRANT_RESULT=PASS", "UID_AFTER_GRANT=",
                   "INIT_MNT_NS=PASS", "EXEC_HANDOFF=ENTER"):
        if signal not in su_core_code:
            fail("the child transport lost physical diagnostic %r" % signal)
    # --- Samsung boot-health handshake around the soft reboot ---------------
    #
    # The 2026-10-01 cycle: the dispatch WORKED (ksud ran, the framework
    # restarted, the UI came back) and the device then full-rebooted on its own
    # with reboot,rollback_staged_install(bootchecker_timeout) after CrashRecovery
    # classified the stall as NATIVE_CRASH. The firmware's own bootchecker.rc
    # zeroes dev.platform_bootcomplete and restarts its watchdog on
    # init.svc.zygote=restarting, which an emulated soft reboot necessarily
    # produces. None of this can be unit-tested through Kotlin here, and the two
    # halves of the record are written by two different processes - the second
    # exists only because the first was killed - so the wiring is guarded
    # statically (AGENTS.md section 5).
    health_policy_src = dfr_source("SoftRebootHealthPolicy.java")
    health_src = dfr_source("SoftRebootHealth.kt")
    health_policy_code = code_only(health_policy_src)
    health_code = code_only(health_src)
    for prop in ("sys.boot_completed", "dev.bootcomplete", "dev.platform_bootcomplete",
                 "init.svc.zygote", "init.svc.bootchecker", "init.svc.bootchecker-bootc",
                 "crashrecovery.attempting_reboot", "sys.init.updatable_crashing"):
        if '"%s"' % prop not in health_policy_code:
            fail("SoftRebootHealthPolicy no longer pins %r; the Samsung half of the "
                 "boot-completion handshake is what timed out on 2026-10-01" % prop)
    # An unset property and an unreadable one are different facts: collapsing them
    # either makes the gate unsatisfiable (a healthy boot leaves the two crash
    # signals unset) or makes an unreadable crash signal look like a clean one.
    if 'ABSENT = "ABSENT"' not in health_policy_code \
            or 'UNKNOWN = "UNKNOWN"' not in health_policy_code:
        fail("SoftRebootHealthPolicy collapsed 'unset' and 'unreadable' into one "
             "value; one of them is a reading and the other is a refusal")
    for verdict in ("BOOT_HEALTH_CONVERGED", "BOOT_HEALTH_PENDING",
                    "BOOT_HEALTH_CRASH_RECOVERY", "BOOT_HEALTH_UNKNOWN",
                    "BOOT_HEALTH_NOT_APPLICABLE"):
        if verdict not in health_policy_code:
            fail("SoftRebootHealthPolicy lost the distinct verdict %r" % verdict)
    # --- the off-target escape, and why it cannot be reached on the target ---
    # This is a Samsung mechanism and Apply Modules is reachable off-target (a
    # generic device running the bundled daemon can satisfy PostRootStatus), so an
    # unconditional Samsung gate would refuse it on every device but this one -
    # AGENTS.md section 1: an unrelated device takes the unchanged upstream path.
    # The escape must stay narrow: ALL the OEM-only properties positively unset,
    # with AOSP's own flag saying the boot completed.
    if "OEM_ONLY" not in health_policy_code:
        fail("SoftRebootHealthPolicy no longer names the OEM-only properties, so "
             "NOT_APPLICABLE is no longer tied to the mechanism's absence")
    else:
        oem_block = health_policy_code[health_policy_code.find("OEM_ONLY = List.of("):]
        oem_block = oem_block[:oem_block.find(");") + 2]
        for prop in ("PROP_DEV_PLATFORM_BOOTCOMPLETE", "PROP_INIT_SVC_BOOTCHECKER",
                     "PROP_INIT_SVC_BOOTCHECKER_BOOTC"):
            if prop not in oem_block:
                fail("%s is no longer one of the OEM-only properties; the "
                     "NOT_APPLICABLE escape would widen" % prop)
    if "if (!oemPresent) return NOT_APPLICABLE;" not in health_policy_code:
        fail("NOT_APPLICABLE is no longer conditioned on the OEM mechanism being "
             "positively absent; a partially present mechanism must stay PENDING")
    # CrashRecovery is AOSP's, not the OEM's: a rollback in flight is a bad moment
    # for a userspace teardown on any device, so it must outrank applicability.
    crash_at = health_policy_code.find("return CRASH_RECOVERY;")
    na_at = health_policy_code.find("if (!oemPresent) return NOT_APPLICABLE;")
    unknown_at = health_policy_code.find("if (UNKNOWN.equals(s.get(p))) return HEALTH_UNKNOWN;")
    if not (0 <= unknown_at < crash_at < na_at):
        fail("verdict() no longer checks unreadable properties, then CrashRecovery, "
             "then applicability in that order; an unreadable crash signal would "
             "read as PENDING or a rollback as 'not a candidate'")
    # --- the post half must be re-samplable until it settles ----------------
    # BOOT_COMPLETED can arrive while dev.platform_bootcomplete is still 0 and
    # bootchecker-bootc is still `running`. A record frozen on that first sample
    # would make a transient PENDING indistinguishable from the minutes-long
    # failure under investigation - the exact collapse this file exists to stop.
    for required in ("post_first_verdict", "post_observations", "post_settled",
                     "post_converged_seen", "post_crash_recovery_seen"):
        if required not in health_policy_code:
            fail("SoftRebootHealthPolicy no longer records the post half's history "
                 "(%r missing); one sample would be reported as the answer" % required)
    # The window closes on TIME, never on a verdict. A first CONVERGED proves no
    # more than a first PENDING: the device that produced this investigation had a
    # converged-looking userspace for minutes before CrashRecovery rolled it back,
    # so stopping at the first good answer would report the hypothesis refuted on
    # evidence that does not refute it.
    if "terminal(" in health_policy_code:
        fail("SoftRebootHealthPolicy is back to treating some verdict as terminal; "
             "a first CONVERGED would close the window two minutes before the "
             "observed failure arrived")
    if 'if (!"0".equals(parsed.get(KEY_POST_SETTLED))) return null;' \
            not in health_policy_code:
        fail("a post half whose window has closed can be overwritten; a later "
             "observation would be presented as the decisive one")
    for sticky in ("convergedSeen = \"1\".equals(parsed.get(KEY_POST_CONVERGED_SEEN))",
                   "crashSeen = \"1\".equals(parsed.get(KEY_POST_CRASH_SEEN))"):
        if sticky not in health_policy_code:
            fail("the post half's seen-flags are no longer sticky (%r missing); a "
                 "CONVERGED later followed by a rollback would lose one of the two "
                 "facts" % sticky)
    # --- a stored verdict must be re-derivable from the stored evidence -------
    # Without this a file could say pre_verdict=BOOT_HEALTH_CONVERGED over
    # pre_dev_platform_bootcomplete=0 and parse cleanly: a verdict with no
    # evidence behind it, which AGENTS.md section 2 says must refuse.
    if "halfIsSelfConsistent" not in health_policy_code \
            or "stored.equals(verdict(rebuilt))" not in health_policy_code:
        fail("the parser trusts each half's stored verdict instead of recomputing "
             "it from that half's own stored properties")
    if "validNumeric" not in health_policy_code \
            or "if (start >= 0 && end >= 0 && end < start) return false;" \
            not in health_policy_code:
        fail("numeric record fields are no longer domain-checked; junk would parse "
             "and a property sweep could claim to end before it began")
    # A failed reading is the literal UNKNOWN, never -1: the repository already
    # learned that in EarlyBootProbePolicy.
    if "numericField" not in health_policy_code:
        fail("a failed reading is written as a number again; a numeric -1 is not a "
             "second spelling of UNKNOWN and a parser cannot refuse it")
    # --- telemetry is recorded, never gated on -------------------------------
    for prop in ("sys.init.updatable_crashing_process_name", "dev.attempting_reboot"):
        if '"%s"' % prop not in health_policy_code:
            fail("SoftRebootHealthPolicy no longer records %r; the incident's "
                 "CrashRecovery entry named bootchecker_timeout, which the boolean "
                 "alone cannot say" % prop)
    if "TELEMETRY" not in health_policy_code:
        fail("the telemetry-only properties are no longer separated from the gating "
             "ones; an unreadable diagnostic would refuse a dispatch")
    verdict_body = health_policy_code[
        health_policy_code.find("public static String verdict("):
        health_policy_code.find("public static String formatPreExec(")]
    if "TELEMETRY" in verdict_body or "ALL_PROPERTIES" in verdict_body:
        fail("verdict() consults the telemetry-only properties; nothing decides "
             "anything from them, so an unreadable one must refuse nothing")
    # --- the format is versioned --------------------------------------------
    # The record outlives the app version that wrote it, so "a build using another
    # format" and "a corrupt file" are different facts.
    if "SCHEMA_VERSION" not in health_policy_code \
            or "OBS_OTHER_SCHEMA" not in health_policy_code:
        fail("the boot-health record is no longer versioned; an older schema and a "
             "damaged file would be the same observation")
    # --- an equal pid is not evidence of the same process -------------------
    if "PROC_UNDECIDED" not in health_policy_code \
            or "proc_starttime" not in health_policy_code:
        fail("process identity across the restart is inferred from the pid alone; "
             "pids are reused, so an equal pid is not evidence of survival")
    # --- what this process can say about the exec itself --------------------
    # The pre half is written BEFORE the exec, so on its own it proves the exec was
    # reached, never that a soft reboot was dispatched. Every path that returns
    # alive must say so, or a record that executed nothing reads as a framework
    # that never came back.
    for required in ("EXEC_NOT_REACHED", "EXEC_NOT_ATTEMPTED", "EXEC_REFUSED_DIGEST",
                     "EXEC_TRANSPORT_LOST", "EXEC_UNDETERMINED", "EXEC_FAILED",
                     "EXEC_RETURNED"):
        if required not in health_policy_code:
            fail("SoftRebootHealthPolicy lost the exec outcome %r; a refusal and a "
                 "teardown would leave the same record" % required)
    if "EXEC_NOT_REACHED.equals(parsed.get(KEY_EXEC_OUTCOME))" not in health_policy_code:
        fail("the exec outcome can be written twice; the first write came from the "
             "code path that actually took the call")
    # Set.of() is null-hostile: contains(null) throws, and a record missing the key
    # arrives here with null. A parser whose job is to refuse must not throw.
    if "execOutcome == null || !EXEC_OUTCOMES.contains(execOutcome)" \
            not in health_policy_code:
        fail("parse() calls Set.of().contains() on a possibly absent exec outcome; "
             "that throws NullPointerException instead of refusing")
    # The two halves must stay separable, and the post half must never be
    # writable over another boot's record or over an already complete one.
    for required in ('PHASE_PRE_EXEC = "PRE_EXEC"', 'PHASE_POST_EXEC = "POST_EXEC"',
                     "if (!PHASE_PRE_EXEC.equals(parsed.get(KEY_PHASE))) return null;",
                     "if (!currentBootId.equals(parsed.get(KEY_BOOT_ID))) return null;"):
        if required not in health_policy_code:
            fail("SoftRebootHealthPolicy no longer keeps the pre- and post-teardown "
                 "halves apart (%r missing); a second observation would be written "
                 "as the first" % required)
    if "OBS_STALE_BOOT" not in health_policy_code \
            or "OBS_PRE_EXEC_ONLY" not in health_policy_code:
        fail("SoftRebootHealthPolicy no longer separates a record from an earlier "
             "boot from a dispatch whose framework never came back; soft-reboot "
             "artefacts survive a full reboot, so those are different facts")
    # The Kotlin side observes and persists; it must never decide.
    for banned in ('= SoftRebootHealthPolicy.CONVERGED', 'CONVERGED)',
                   'bootHealthVerdict ='):
        if banned in health_code:
            fail("SoftRebootHealth derives or asserts the converged verdict (%r); "
                 "the classification belongs to the pure, tested policy" % banned)
    if "SoftRebootHealthPolicy.unreadableSnapshot(" not in health_code:
        fail("SoftRebootHealth no longer produces an all-UNKNOWN snapshot when "
             "SystemProperties cannot be reached; a partial read would gate")
    # The bounded settle observer, and the two properties that keep it honest: it
    # is not on the broadcast's thread (a pending result has a deadline in
    # seconds), and only one may run (two would race each other into the record).
    for required in ("SETTLE_DEADLINE_MS", "SETTLE_INTERVAL_MS", "settling",
                     "compareAndSet(false, true)", "isDaemon = true",
                     "readStartMs", "readEndMs", "procStarttime"):
        if required not in health_code:
            fail("SoftRebootHealth no longer runs exactly one bounded, detached "
                 "settle observer (%r missing)" % required)
    # The sweep is N sequential property reads, not one instant. Recording both
    # ends is what keeps the record from claiming an atomicity it does not have.
    if "snapshot.readEndMs = monotonic()" not in health_code:
        fail("SoftRebootHealth records only one end of the property sweep; the "
             "record would claim an instant it never had")
    # --- the window's deadline is a property of the RECORD -------------------
    # A deadline held in the observer's local memory made post_settled=0 mean both
    # "still inside the window" and "the observer died and nobody can tell", and
    # let a framework restart begin a second five minutes on top of the first.
    if "post_window_opened_ms" not in health_policy_code \
            or "windowExpired(" not in health_policy_code:
        fail("the observation window has no durable anchor; nothing outside the "
             "observing process could decide whether it had expired")
    if "val startedAt = monotonic()" in health_code \
            or "startedAt + SETTLE_DEADLINE_MS" in health_code:
        fail("the settle observer is back to timing its window from a local start; "
             "a process restart would start a second window on top of the first")
    for caller in ("SoftRebootHealthPolicy.windowExpired(",):
        if health_code.count(caller) < 2:
            fail("the record's own deadline is not consulted by both the observer "
                 "and the UI re-sample; a dead observer would leave the window "
                 "open for the rest of the boot")
    # A window that cannot be timed must not be left open.
    if "windowClosed || windowOpenedMs < 0" not in health_policy_code:
        fail("a boot-health window with no anchor stays open; nothing could ever "
             "decide it had expired")
    # --- the observer must persist an EVIDENCE change, not a verdict change ---
    if "postEvidenceUnchanged(" not in health_policy_code \
            or "postEvidenceUnchanged(" not in health_code:
        fail("the settle observer persists only verdict changes; "
             "dev.platform_bootcomplete can move 0 -> 1 while the verdict stays "
             "PENDING, which is exactly the transition being measured")
    if "verdict == before.postVerdict" in health_code:
        fail("the settle observer is back to comparing verdicts to decide whether "
             "to persist a sample")
    for sticky in ("post_platform_bootcomplete_seen", "post_dev_bootcomplete_seen"):
        if sticky not in health_policy_code:
            fail("the record has no sticky for %r; a 0 -> 1 -> 0 excursion of the "
                 "property the experiment asks about would vanish" % sticky)
    # --- one mutation authority for the record -------------------------------
    # Two unsynchronised read-modify-writers (the observer and the UI re-sample)
    # could both read one record, both format a successor, and the later write
    # would silently discard the earlier one's observations and sticky flags.
    if "recordLock" not in health_code:
        fail("the boot-health record has no single mutation authority; the "
             "observer and the UI re-sample would lose each other's updates")
    else:
        for mutator in ("fun recordPreExec(", "fun recordExecOutcome(",
                        "fun completePostExec(", "fun resample("):
            at = health_code.find(mutator)
            if at < 0:
                fail("SoftRebootHealth no longer defines %s" % mutator)
                continue
            body = health_code[at:at + 900]
            if "synchronized(recordLock)" not in body:
                fail("%s mutates the boot-health record without holding the "
                     "record lock across its read-modify-write" % mutator)
    if 'target.name + ".tmp." + tempSequence' not in code_only(autoroot_store_src):
        fail("AutoRootStore stages every write under one <target>.tmp again; two "
             "writers of one record can interleave the write, the read-back and "
             "the rename")
    # --- the guard must not be able to stick --------------------------------
    start_at = health_code.find("fun startSettleObserver(")
    start_body = health_code[start_at:health_code.find("private fun settleLoop(")] \
        if start_at >= 0 else ""
    if "settling.set(false)" not in start_body.split("val thread = Thread(")[0] \
            and start_body.count("settling.set(false)") < 2:
        fail("a failed Thread.start() leaves the settle guard latched true for the "
             "life of the process; every later observation would be skipped")
    # --- an unversioned record is not evidence of an older format ------------
    # This record shipped with its version line, so no build ever wrote one
    # without it, and a truncated file loses exactly that line.
    if "return false;\n    }" not in health_policy_code.split("otherSchema(String record)")[1][:1200]:
        fail("otherSchema() still reports a record with no version line as another "
             "build's format; that turns unknown corruption into 'intact'")
    # --- the UI may not be more certain than the record ---------------------
    for ambiguous in ("SoftRebootHealthPolicy.EXEC_UNDETERMINED ->",
                      "SoftRebootHealthPolicy.EXEC_RETURNED ->"):
        if ambiguous not in health_code:
            fail("the operator line collapses %s into a definite 'nothing was "
                 "handed over'; the policy documents it as ambiguous" % ambiguous)
    if "lastIndexOf(')')" not in health_code:
        fail("the /proc/self/stat parse no longer skips the comm field; field 2 can "
             "contain spaces and parentheses, so splitting the line is wrong")
    if "fun resample(" not in health_code:
        fail("nothing re-samples the post half from the UI; the operator opening "
             "the app minutes after a dispatch is the most valuable observation")
    # --- the gate itself ----------------------------------------------------
    if "public String bootHealthVerdict = SoftRebootHealthPolicy.HEALTH_UNKNOWN;" \
            not in soft_policy_code:
        fail("SoftRebootPolicy.Inputs no longer defaults the boot-health verdict to "
             "the refusing value; a caller that forgot to supply it would be "
             "permitted")
    if "permitsDispatch" not in health_policy_code:
        fail("SoftRebootHealthPolicy no longer owns the single definition of which "
             "verdicts permit a dispatch; two copies are how the gate and the "
             "boundary re-read drift apart")
    if "if (!SoftRebootHealthPolicy.permitsDispatch(in.bootHealthVerdict))" \
            not in soft_policy_code:
        fail("SoftRebootPolicy no longer refuses a dispatch from a boot whose "
             "firmware boot-health handshake does not permit one")
    for banned in ("PENDING.equals(in.bootHealthVerdict)",
                   "HEALTH_UNKNOWN.equals(in.bootHealthVerdict)",
                   "CRASH_RECOVERY.equals(in.bootHealthVerdict)"):
        if banned in soft_policy_code:
            fail("SoftRebootPolicy admits a boot-health verdict other than the "
                 "permitted ones (%r)" % banned)
    # In preCandidateChecks, so the unprivileged precheck refuses on it too - a
    # gate only in evaluate() would still have spawned a root shell first.
    pre_checks = soft_policy_code.find("private static Decision preCandidateChecks(")
    select = soft_policy_code.find("private static Decision selectBinary(")
    gate_at = soft_policy_code.find("in.bootHealthVerdict))")
    if pre_checks < 0 or select < 0 or not (pre_checks < gate_at < select):
        fail("the boot-health gate is not in SoftRebootPolicy's unprivileged "
             "precheck; a refused dispatch would obtain a root shell first")
    # --- one reading, used twice -------------------------------------------
    # The state that permitted the dispatch and the state the record reports have
    # to be the same reading, or the record says nothing about the decision.
    # Scope BEFORE measuring: the handshake is an OEM mechanism, and on a device
    # that asserts neither the pinned model nor the codename there is nothing to
    # measure (AGENTS.md section 1). Inferring that from the properties alone let a
    # failed lookup (UNKNOWN) or a name-sharing ROM (PENDING) refuse a dispatch on
    # a path that previously made no such reading.
    if "SoftRebootHealth.targetAnchorAsserted()" not in soft_receiver_code \
            or "if (anchorAsserted) SoftRebootHealth.snapshot() else null" \
            not in soft_receiver_code:
        fail("DfrSoftRebootReceiver sweeps the OEM boot-health properties on every "
             "device; an unrelated device must take the unchanged upstream path")
    anchor_at = health_code.find("fun targetAnchorAsserted()")
    anchor_body = health_code[anchor_at:anchor_at + 400] if anchor_at >= 0 else ""
    if "Build.MODEL == TARGET_MODEL || Build.DEVICE == TARGET_DEVICE" not in anchor_body:
        fail("the scope test is no longer the profile's own anchor rule "
             "(model_ok || device_ok)")
    if "catch" not in anchor_body or "true" not in anchor_body.split("catch")[1]:
        fail("unreadable device identity takes the OUT-of-scope branch; 'I could "
             "not tell what device this is' must never disable a safety check")
    if "SoftRebootHealth.targetAnchorAsserted()" not in receiver_code:
        fail("DfrBootReceiver completes the boot-health record off-target; that "
             "path writes no record and has nothing to complete")
    if "SoftRebootHealthPolicy.verdict(healthSnapshot)" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer gates on the one boot-health reading "
             "it records")
    # ... and the gate again at the boundary it guards. The decision snapshot is
    # taken before staging, a root shell, two hashes and a durable claim, so it can
    # be seconds stale by the time the exec happens.
    if "SoftRebootHealth.liveVerdict()" not in soft_receiver_code \
            or "SoftRebootHealthPolicy.permitsDispatch(finalVerdict)" \
            not in soft_receiver_code \
            or "SoftRebootHealthPolicy.EXEC_REFUSED_HEALTH" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver never re-reads the boot-health state at the "
             "dispatch boundary; a rollback starting during the staging would be "
             "missed by the only gate that looks")
    boundary_at = soft_receiver_code.find("SoftRebootHealth.liveVerdict()")
    pre_at = soft_receiver_code.find("SoftRebootHealth.recordPreExec(")
    exec_at = soft_receiver_code.find("transport.execPinnedDaemon(")
    if not (0 <= pre_at < boundary_at < exec_at):
        fail("the boundary boot-health re-read is not between the pre-teardown "
             "record and the exec; the decision snapshot must stay in the record "
             "and the fresh reading must gate the call")
    if soft_receiver_code.count("SoftRebootHealth.snapshot()") != 1:
        fail("DfrSoftRebootReceiver takes more than one boot-health reading; the "
             "gated state and the recorded state would be different states")
    if "SoftRebootHealth.recordPreExec(bootId, healthSnapshot)" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer writes the pre-teardown boot-health "
             "half; the process that could report the outcome is the one `stop` "
             "kills")
    # Before the exec, and a failure to persist it refuses - the same rule the
    # soft-reboot trace already follows, for the same reason.
    health_write = soft_receiver_code.find("SoftRebootHealth.recordPreExec(")
    exec_call = soft_receiver_code.find("transport.execPinnedDaemon(")
    if health_write < 0 or exec_call < 0 or health_write > exec_call:
        fail("the pre-teardown boot-health record is written after the exec; it "
             "exists to survive that exec, so it must precede it")
    if "if (healthFailure != null) {" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver treats a failed boot-health write as telemetry; "
             "it is the pre-operation record for an operation that has already "
             "taken this device down once with nothing readable afterwards")
    # Every path that returns with this process alive executed nothing (or cannot
    # say), and has to record that: the pre half alone proves only that the exec
    # was reached. Both the refusal before the call and the outcome after it.
    if "SoftRebootHealthPolicy.EXEC_NOT_ATTEMPTED" not in soft_receiver_code:
        fail("DfrSoftRebootReceiver no longer records that a refusal landed before "
             "the exec; that record would later read as a torn-down framework")
    for required in ("SoftRebootHealth.recordExecOutcome(bootId, when {",
                     "SoftRebootHealthPolicy.EXEC_REFUSED_DIGEST",
                     "SoftRebootHealthPolicy.EXEC_TRANSPORT_LOST",
                     "SoftRebootHealthPolicy.EXEC_UNDETERMINED",
                     "SoftRebootHealthPolicy.EXEC_FAILED",
                     "SoftRebootHealthPolicy.EXEC_RETURNED"):
        if required not in soft_receiver_code:
            fail("DfrSoftRebootReceiver no longer records what it saw of the exec "
                 "(%r missing); an exec that refused and a teardown would leave "
                 "the same record" % required)
    outcome_at = soft_receiver_code.find("SoftRebootHealth.recordExecOutcome(bootId, when {")
    if outcome_at < 0 or outcome_at < exec_call:
        fail("the exec outcome is recorded before the exec; it is a fact about the "
             "call's return and reaching it at all means no teardown took us")
    # --- the post half, written by the only observer that exists ------------
    if "SoftRebootHealth.completePostExec(bootId)" not in receiver_code:
        fail("DfrBootReceiver no longer completes the soft-reboot boot-health "
             "record; nothing would observe what the firmware made of the restart")
    if "SoftRebootHealth.startSettleObserver(bootId)" not in receiver_code:
        fail("DfrBootReceiver takes one post sample and stops; BOOT_COMPLETED is "
             "the first moment convergence is POSSIBLE, not guaranteed, so a "
             "transient PENDING would be frozen as the measurement")
    if "!o.postWindowClosed" not in receiver_code \
            or "SoftRebootHealthPolicy.OBS_POST_EXEC" not in receiver_code:
        fail("DfrBootReceiver starts the settle observer without checking that "
             "there is an open window to observe")
    # The observer must not run on the receiver's shared single-thread worker: that
    # executor also carries the early-boot evidence, and a goAsync() pending result
    # has a deadline in seconds.
    settle_src = health_code[health_code.find("private fun settleLoop("):]
    if "Thread.sleep(" not in settle_src:
        fail("the settle observer no longer paces itself")
    if "worker.execute" in health_code:
        fail("the settle observer runs on the BroadcastReceiver's shared worker; a "
             "multi-minute poll there serialises unrelated work behind it")
    if "if (booted) completeSoftRebootHealth()" not in receiver_code:
        fail("DfrBootReceiver samples boot health outside BOOT_COMPLETED; "
             "LOCKED_BOOT_COMPLETED arrives before sys.boot_completed is 1, so the "
             "one write the record gets would be spent on a reading that cannot "
             "converge")
    post_at = receiver_code.find("if (booted) completeSoftRebootHealth()")
    worker_at = receiver_code.find("val task = Runnable {")
    if post_at < 0 or worker_at < 0 or post_at < worker_at:
        fail("DfrBootReceiver completes the boot-health record on the main looper; "
             "this app runs in system_server and the write costs two fsyncs")
    if "/data/system/dfreroot-softreboot-health" not in autoroot_store_src:
        fail("AutoRootStore no longer stores the soft-reboot boot-health record "
             "where this process can write it before the teardown")
    # --- the marker chip must say which of the three states it means --------
    # Once root is established on ZZIC the /dev/df* probes return EACCES, not
    # ENOENT, so the collapsed chip printed HOOKED - a definite claim - while the
    # dialog refused with "cannot determine whether a stage marker exists".
    main_code = code_only(main_src_holder[0])
    chip_fn = main_code.find("private fun updateChip()")
    chip_body = main_code[chip_fn:main_code.find("private fun showRunDialog()")] \
        if chip_fn >= 0 else ""
    if not chip_body:
        fail("MainActivity.updateChip() not found; the marker chip cannot be checked")
    else:
        for required in ("AutoRootPolicy.MARKER_ABSENT", "AutoRootPolicy.MARKER_PRESENT",
                         "R.string.chip_marker_unknown"):
            if required not in chip_body:
                fail("MainActivity.updateChip() no longer distinguishes all three "
                     "marker states (%r missing); an undeterminable probe would be "
                     "displayed as a definite HOOKED" % required)
        if "markerState() != AutoRootPolicy.MARKER_ABSENT" in chip_body:
            fail("MainActivity.updateChip() collapsed the marker states back into "
                 "ABSENT-or-not; PRESENT and UNKNOWN are different facts")
    autoroot["soft_reboot_boot_health"] = "gated+recorded"

    rcv2 = re.search(r"<receiver[^>]*DfrSoftRebootReceiver[^>]*/?>", manifest_code)
    if not rcv2:
        fail("DfrSoftRebootReceiver is not declared in the manifest")
    elif 'android:exported="false"' not in rcv2.group(0):
        fail("DfrSoftRebootReceiver is exported; an external component must not be "
             "able to ask for a soft reboot")
    else:
        autoroot["soft_reboot_receiver_exported"] = "false"

    # Observation-only persisted early-job experiment. The scheduler binding is
    # exported under the signature BIND_JOB_SERVICE permission; the service may
    # inspect readiness but may never reach any destructive/root entry point.
    early_job_src = dfr_source("DfrEarlyBootJobService.kt")
    early_arm_src = dfr_source("DfrEarlyBootProbe.kt")
    stage_hop_src = dfr_source("StageHop.kt")
    job_service = re.search(
        r"<service[^>]*DfrEarlyBootJobService[^>]*/>", manifest_code, flags=re.S)
    if not job_service:
        fail("DfrEarlyBootJobService is not declared in the manifest")
    else:
        declaration = job_service.group(0)
        for required in ('android:permission="android.permission.BIND_JOB_SERVICE"',
                         'android:directBootAware="true"',
                         'android:exported="true"'):
            if required not in declaration:
                fail("DfrEarlyBootJobService manifest boundary is missing %s" % required)
    for forbidden in ("DfrRootCoordinator", "DirtyFrag", "hopToNetworkStack",
                      "RootTransport", "soft-reboot", "APPLY_MODULES",
                      "transact(5"):
        if forbidden in code_only(early_job_src):
            fail("DfrEarlyBootJobService references destructive/root entry point %r"
                 % forbidden)
    for required in ("setPersisted(true)", "setMinimumLatency(MINIMUM_LATENCY_MS)",
                     "forNamespace(NAMESPACE)", "getPendingJob(JOB_ID)",
                     "existing.service != component"):
        if required not in code_only(early_arm_src):
                fail("early-job arming lost identity/persistence guard %r" % required)
    for required in ("it.jobId == jobId", "it.jobId == DfrEarlyBootProbe.JOB_ID",
                     "it.namespace == expectedNamespace",
                     # The literal was refactored into a shared constant; accept
                     # either spelling so the guard tracks the property, not one
                     # way of writing it. A guard that fails on correct code
                     # gets weakened or deleted, which is how the property is
                     # really lost.
                     ('namespaceBinding == "PASS"',
                      'namespaceBinding == EarlyBootProbePolicy.SIGNAL_PASS')):
        alternatives = required if isinstance(required, tuple) else (required,)
        if not any(alt in code_only(early_job_src) for alt in alternatives):
            fail("early-job callback accepts an unbound arm record: missing %r"
                 % (required,))
    if "EARLY_JOB_LOCKED_BOOT_PENDING" not in dfr_source("EarlyBootProbePolicy.java") \
            or "EarlyBootProbeStore.finalizeFromStoredLockedBoot(bootId)" \
                not in boot_receiver_src:
        fail("an absent locked-boot marker can be promoted without a later "
             "monotonic timestamp comparison")

    # --- the probe must not perturb what it measures ------------------------
    # This app runs with android:process="system", so the JobService callback and
    # DfrBootReceiver are both delivered on system_server's main looper. Heavy
    # work in either one delays the other, and the one thing this experiment
    # measures is which of the two happened first. An inline probe would
    # manufacture its own early callback. None of this compiles here, so the
    # shape is asserted statically or not at all.
    early_job_code = code_only(early_job_src)
    store_code = code_only(dfr_source("EarlyBootProbeStore.kt"))

    def order(code, *needles):
        """Index of each needle, or None when one is absent."""
        found = [code.find(n) for n in needles]
        return None if -1 in found else found

    for required in ("val callbackElapsedMs = monotonicNow()",
                     "worker.execute(task)", "return true", "jobFinished(params, false)"):
        if required not in early_job_code:
            fail("the early-job callback no longer offloads its work: missing %r"
                 % required)
    positions = order(early_job_code,
                      "val callbackElapsedMs = monotonicNow()",
                      "val task = Runnable {",
                      "EarlyBootProbeStore.writeCallbackEntered",
                      "StageHop.probeReadiness",
                      "EarlyBootProbeStore.writeProbe")
    if positions is None or positions != sorted(positions):
        fail("the early-job callback reads its clock, or does readiness/marker "
             "work, outside the worker - it would delay the LOCKED_BOOT "
             "broadcast it is timing itself against")
    # The breadcrumb must precede the slow readiness sweep, or it cannot
    # separate "never fired" from "fired and died before the record".
    if "EarlyBootProbePolicy.CALLBACK_ENTERED" not in early_job_code:
        fail("the early-job callback writes no entry breadcrumb; an absent "
             "probe record would collapse two different outcomes")
    if 'appendLine("stopped=' not in early_job_code \
            or "override fun onStopJob" not in early_job_code:
        fail("the early-job record cannot distinguish a stopped job from a "
             "slow one")

    # --- JobScheduler lifecycle --------------------------------------------
    # After onStopJob the platform has ended that execution, so reporting
    # completion afterwards is a claim about a job that is no longer ours. And
    # the platform keeps ONE instance of the service across callbacks, so
    # per-run state must not live in an instance field: a `stopped` flag set
    # once would still read true on a later run that was never stopped.
    if "completeOnMain(params, token)" not in early_job_code \
            or "completionHandler.post" not in early_job_code \
            or early_job_code.count("jobFinished(params, false)") != 1:
        fail("early-job completion is no longer serialized with onStopJob on "
             "the main looper; a worker-side check-then-finish reopens the race")
    task_start = early_job_code.find("val task = Runnable {")
    task_end = early_job_code.find("try {\n            worker.execute(task)", task_start)
    if task_start < 0 or task_end < 0 \
            or "jobFinished(params, false)" in early_job_code[task_start:task_end]:
        fail("the early-job worker calls jobFinished directly instead of posting "
             "the lifecycle decision to the main looper")
    if "private class RunToken" not in early_job_code \
            or "AtomicBoolean(false)" not in early_job_code:
        fail("the early-job callback holds cancellation state per service "
             "instance instead of per run; it would leak into the next job")
    if re.search(r"^\s*private var stopped\b", early_job_code, flags=re.M):
        fail("a service-instance `stopped` field is back; it never resets "
             "between executions")
    # Call sites only: counting every occurrence of the name would include the
    # declaration, so four boundaries plus one definition reads as five and a
    # deleted boundary still reads as four. A guard that survives the
    # regression it exists for is not a guard.
    if early_job_code.count("if (abandonIfStopped(") < 4:
        fail("the early-job worker does not check for cancellation at its "
             "boundaries; a stopped run would still pay for the readiness "
             "sweep it was told to abandon")

    # --- no fallback may reproduce the defect the path exists to remove -----
    if "task.run()" in receiver_code:
        fail("DfrBootReceiver runs the early-job marker inline when the worker "
             "is unavailable; the failure path would put two fsyncs back on "
             "system_server's main looper")
    if "reason=worker_unavailable" not in receiver_code:
        fail("a rejected early-job worker no longer records that the marker "
             "was refused rather than written")

    # --- a transient finalize failure gets one late, uninvolved retry -------
    if "private fun retryPendingFinalize()" not in receiver_code \
            or "EarlyBootProbePolicy.LOCKED_PENDING" not in receiver_code:
        fail("nothing retries a PENDING probe record after a transient "
             "finalize failure; the verdict would sit unmade in two files")
    if "recordLockedBoot(arrivalMs) else retryPendingFinalize()" \
            not in receiver_code:
        fail("the BOOT_COMPLETED retry writes a timestamp or a marker; it may "
             "only complete an ordering the stored timestamps already imply")
    if "optin_start_ms=" not in receiver_code:
        fail("the receiver's dispatch cost is no longer measured; whether "
             "optInVerdict() delays Auto Root would stay a guess")
    start_job = early_job_code.find("override fun onStartJob")
    start_body = early_job_code[start_job:early_job_code.find("override fun onStopJob")]
    for banned in ("StageHop.", "EarlyBootProbeStore.", "readBootId()", "readFile("):
        if banned in start_body.split("val task = Runnable {")[0]:
            fail("onStartJob does blocking work (%r) before handing off to the "
                 "worker" % banned)

    # The same rule for the receiver: Auto Root is dispatched first, and the
    # marker - two fsyncs and a read-modify-write - happens afterwards, on a
    # worker, and only while the experiment is armed.
    for required in ("goAsync()", "persistLockedBootEvidence(action, arrivalMs)",
                     "EarlyBootProbeStore.readArm()", "worker.execute(task)"):
        if required not in receiver_code:
            fail("DfrBootReceiver no longer keeps the early-job marker off the "
                 "Auto Root critical path: missing %r" % required)
    receiver_order = order(receiver_code,
                           "DfrAutoRootService::class.java",
                           "persistLockedBootEvidence(action, arrivalMs)")
    if receiver_order is None or receiver_order != sorted(receiver_order):
        fail("DfrBootReceiver persists early-job telemetry before dispatching "
             "Auto Root; the instrumentation would delay the flow it measures")
    on_receive = receiver_code.find("override fun onReceive")
    on_receive_body = receiver_code[
        on_receive:receiver_code.find("private fun persistLockedBootEvidence")]
    if "EarlyBootProbeStore.recordLockedBoot" in on_receive_body:
        fail("DfrBootReceiver writes the locked-boot marker synchronously in "
             "onReceive")

    # --- evidence convergence and clock honesty -----------------------------
    # Both workers finalize, so the verdict follows the timestamps rather than
    # whichever thread happened to finish last.
    if "EarlyBootProbeStore.finalizeFromStoredLockedBoot(firedBootId)" \
            not in early_job_code:
        fail("the early-job callback does not re-check the locked-boot marker "
             "after writing its record; a record written in the race window "
             "would stay PENDING for the whole boot")
    if "synchronized(lock)" not in store_code:
        fail("EarlyBootProbeStore no longer serialises its read-modify-write "
             "sequences; two workers in process \"system\" now share it")
    if "EarlyBootProbePolicy.mergeLockedBoot" not in store_code:
        fail("the locked-boot marker is written without the first-timestamp "
             "merge rule; a framework restart could move the comparison point")
    if 'if (elapsedMs < 0) return "monotonic_clock_unavailable"' not in store_code:
        fail("a failed monotonic reading can still be stored as a locked-boot "
             "timestamp; a successful write is not timing evidence")
    # --- one arming cycle at a time ----------------------------------------
    # The one-shot job leaves its arm record on disk after firing, so "the arm
    # record parses" is not "a probe is waiting". Cycle identity comes from
    # arm() archiving the previous cycle's records, never from comparing boot
    # ids: a re-arm in the boot the previous callback fired in makes the stale
    # record's fired_boot_id equal the new arm's armed_boot_id, and any
    # heuristic then reports a freshly pending job as consumed.
    arm_code = code_only(early_arm_src)
    if "EarlyBootProbeStore.archivePreviousCycle()" not in arm_code:
        fail("arming does not archive the previous probe cycle; a stale "
             "callback record would be read as this cycle's result")
    archive_order = order(arm_code, "EarlyBootProbeStore.archivePreviousCycle()",
                          "EarlyBootProbeStore.writeArm(record)")
    if archive_order is None or archive_order != sorted(archive_order):
        fail("arming writes the new arm record before archiving the previous "
             "cycle; the two must never be live together")
    if "probe.firedBootId == arm.armedBootId" in arm_code \
            or "thisCycle" in arm_code:
        fail("the arm-state row infers the probe cycle from boot ids again; "
             "that cannot distinguish a same-boot re-arm from a stale result")
    if "EarlyBootProbePolicy.needsLockedBootMarker(" not in receiver_code \
            or "probeRecord, callbackRecord, bootId" not in receiver_code \
            or "LOCKED_BOOT_MARKER=SKIP cycle already resolved/spent" not in receiver_code:
        fail("DfrBootReceiver no longer distinguishes same-boot PENDING evidence "
             "from a resolved/older cycle; PRE_LOCKED would be unprovable or a "
             "spent probe would cost markers forever")
    if "LOCKED_BOOT_MARKER=SKIP callback already entered" in receiver_code:
        fail("a callback breadcrumb suppresses the same-boot LOCKED_BOOT marker "
             "again; breadcrumb-only is incomplete evidence and needs that timestamp")
    # Shared evidence vocabulary: StageHop and the JobService must use the
    # policy's constants/roll-up rather than maintaining a second spelling that
    # can drift away from the parser.
    stage_hop_code = code_only(stage_hop_src)
    if "EarlyBootProbePolicy.readinessState(" not in stage_hop_code:
        fail("StageHop duplicates the readiness roll-up instead of using the "
             "policy that validates its durable record")
    for literal in ("NETWORKSTACK_READY", "NETWORKSTACK_PARTIAL",
                    "NETWORKSTACK_NOT_READY"):
        if ('"' + literal + '"') in stage_hop_code:
            fail("StageHop hard-codes readiness state %s instead of sharing the "
                 "policy constant" % literal)
    for literal in ("EARLY_JOB_CALLBACK_ENTERED", "EARLY_JOB_CALLBACK_STOPPED",
                    "before_arm_read", "before_readiness",
                    "after_readiness", "before_marker"):
        if ('"' + literal + '"') in early_job_code:
            fail("DfrEarlyBootJobService duplicates evidence token %s instead of "
                 "sharing EarlyBootProbePolicy" % literal)
    if "EarlyBootProbePolicy.parseCallback(callbackRecord)" not in arm_code:
        fail("the UI treats breadcrumb existence as evidence without strict parsing")

    if "params.jobNamespace" not in early_job_code \
            or "namespace_binding=$namespaceBinding" not in early_job_code:
        fail("the early-job record is not bound to the namespace JobScheduler "
             "actually called back in; uid 1000 is shared")
    if ".invoke(" in code_only(stage_hop_src)[
                code_only(stage_hop_src).find("fun probeReadiness"):
                code_only(stage_hop_src).find("fun hopToNetworkStack")]:
        fail("the early-job readiness probe invokes scheduleReceiver instead of "
             "only resolving it")
    # One-shot: jobFinished(..., false) is the no-reschedule contract, and the
    # service must never build a JobInfo of its own.
    if "jobFinished(params, false)" not in early_job_code \
            or "JobInfo" in early_job_code \
            or "scheduler.schedule(job)" not in code_only(early_arm_src):
        fail("the early-job probe is no longer explicit, one-shot owner arming")

    # --- Early Integrated Root: the dispatch inside the boot animation -------
    #
    # None of this compiles or unit-tests here: it is Kotlin that needs an
    # Android runtime, and the paths that matter happen once per full reboot at
    # 15 seconds into boot, in direct boot, on system_server's main looper. So
    # AGENTS.md 5's rule applies - the shape is asserted statically or not at
    # all. The pure half of the feature is EarlyRootPolicy, driven by
    # tools/tests/EarlyRootPolicyTest.java with one negative case per element;
    # what is left for here is the wiring that test cannot see.
    early_root_policy_src = dfr_source("EarlyRootPolicy.java")
    early_root_job_src = code_only(dfr_source("DfrEarlyRootJobService.kt"))
    early_root_service_src = code_only(dfr_source("DfrEarlyRootService.kt"))
    early_root_arm_src = code_only(dfr_source("DfrEarlyRoot.kt"))
    early_root_store_src = code_only(dfr_source("EarlyRootStore.kt"))
    early_root_dispatch_src = code_only(dfr_source("DfrEarlyRootDispatch.kt"))
    early_root_env_src = code_only(dfr_source("EarlyRootEnv.kt"))

    # The two jobs stay two jobs. The probe exists to time itself against
    # LOCKED_BOOT_COMPLETED, so a root chain on that looper would move the
    # quantity it measures; and a callback that can reach transaction 5 must not
    # be reachable by arming a probe. One shared job id or one service with a
    # mode is how both properties are lost in a single edit.
    for forbidden in ("EarlyRootPolicy", "EarlyRootStore", "DfrEarlyRootService",
                      "DfrEarlyRootDispatch", "DfrEarlyRoot."):
        if forbidden in early_job_code:
            fail("the observation-only probe references the dispatching early-root "
                 "path (%r); the measurement that found this window would stop "
                 "being repeatable and arming a probe could reach the chain"
                 % forbidden)
    probe_ids = re.search(r"EXPECTED_JOB_ID\s*=\s*(0x[0-9a-fA-F]+)",
                          dfr_source("EarlyBootProbePolicy.java"))
    root_ids = re.search(r"EXPECTED_JOB_ID\s*=\s*(0x[0-9a-fA-F]+)",
                         early_root_policy_src)
    if not probe_ids or not root_ids:
        fail("cannot read the probe/early-root job ids")
    elif int(probe_ids.group(1), 16) == int(root_ids.group(1), 16):
        fail("the dispatching job shares the probe's job id; arming a probe would "
             "schedule the chain")

    # Manifest boundaries. The JobService binding is the standard exported one
    # under the signature BIND_JOB_SERVICE permission; the service it starts must
    # never be reachable from outside this package.
    root_job_decl = re.search(
        r"<service[^>]*DfrEarlyRootJobService[^>]*/>", manifest_code, flags=re.S)
    if not root_job_decl:
        fail("DfrEarlyRootJobService is not declared in the manifest")
    else:
        for required in ('android:permission="android.permission.BIND_JOB_SERVICE"',
                         'android:directBootAware="true"',
                         'android:exported="true"'):
            if required not in root_job_decl.group(0):
                fail("DfrEarlyRootJobService manifest boundary is missing %s" % required)
    root_service_decl = re.search(
        r"<service[^>]*DfrEarlyRootService[^>]*/>", manifest_code, flags=re.S)
    if not root_service_decl:
        fail("DfrEarlyRootService is not declared in the manifest")
    else:
        if 'android:exported="false"' not in root_service_decl.group(0):
            fail("DfrEarlyRootService is exported; an external component must not be "
                 "able to ask for a root run inside the boot animation")
        if 'android:directBootAware="true"' not in root_service_decl.group(0):
            fail("DfrEarlyRootService is not directBootAware; it is started before "
                 "the user unlocks and would not be instantiable")

    # The callback gates, then dispatches. It must not become a second copy of
    # the chain: the single execution path is DfrRootCoordinator, reached through
    # the service, which re-derives the whole policy on its own observations.
    for forbidden in ("transact(5", "hopToNetworkStack", "DirtyFrag", "RootTransport",
                      "DfrRootCoordinator.run("):
        if forbidden in early_root_job_src:
            fail("the early-root callback reaches the chain directly (%r) instead of "
                 "dispatching the service that re-derives the gate" % forbidden)
    # --- two triggers, ONE gate-and-dispatch sequence ----------------------
    # There are now two triggers: the persisted job, which fires earlier when it
    # fires at all, and ACTION_LOCKED_BOOT_COMPLETED, which is bounded. A second
    # copy of the sequence would be a second place to forget a gate, which is
    # AGENTS.md 3.2 at the scale of the feature - so the order, the refusals and
    # the cancellation boundaries are asserted on the shared object, and the
    # entry points are asserted to route through it and to assemble no inputs of
    # their own.
    for forbidden in ("transact(5", "hopToNetworkStack", "DirtyFrag", "RootTransport",
                      "DfrRootCoordinator.run("):
        if forbidden in early_root_dispatch_src:
            fail("the early-root dispatch reaches the chain directly (%r) instead of "
                 "starting the service that re-derives the gate" % forbidden)
    gate_order = order(early_root_dispatch_src,
                       "EarlyRootStore.trace(",
                       "EarlyRootPolicy.evaluateArmBinding(",
                       "EarlyRootStore.bindCycle(",
                       "EarlyRootPolicy.evaluateBeforeReadiness(",
                       "StageHop.probeReadiness(",
                       "EarlyRootPolicy.evaluate(",
                       "EarlyRootPolicy.STEP_READINESS_PASS",
                       "EarlyRootStore.claimCycle(",
                       "EarlyRootPolicy.STEP_CLAIMED",
                       "EarlyRootPolicy.STEP_DISPATCHED",
                       "context.startService(")
    if gate_order is None or gate_order != sorted(gate_order):
        fail("the early-root dispatch order drifted: it must record the entry "
             "breadcrumb, refuse on the IMMUTABLE half of the gate, bind the "
             "arming to this boot, only then weigh the transient half, pay for "
             "the AMS sweep, re-evaluate the full gate with its result, claim the "
             "arming exclusively, and only then start the service")
    # The bind sits between the durable half of the gate and the readiness sweep,
    # and both sides of that are load-bearing. Before identity, a device that was
    # never armed would write a cycle record on every boot - the broadcast arrives
    # in every boot now. After readiness, a boot in which the framework was too
    # slow would leave the arming live for the NEXT boot, which is the standing
    # switch docs/EARLY_ROOT.md section 6 says is an owner decision.
    # The bind sits between the two halves of the durable gate, and the split is
    # the invariant. Codex caught this on PR #61: with the bind after the
    # transient checks, a boot that arrived a second too late left the arm record
    # live, and the next boot's LOCKED_BOOT_COMPLETED - which arrives in every
    # boot - ran unarmed. EarlyRootPolicyTest holds the contract that keeps the
    # halves apart; what this asserts is that the dispatcher respects it.
    bind_at = early_root_dispatch_src.find("EarlyRootStore.bindCycle(")
    binding_at = early_root_dispatch_src.find("EarlyRootPolicy.evaluateArmBinding(")
    durable_at = early_root_dispatch_src.find("EarlyRootPolicy.evaluateBeforeReadiness(")
    sweep_at = early_root_dispatch_src.find("StageHop.probeReadiness(")
    if not (0 < binding_at < bind_at < durable_at < sweep_at):
        fail("the early-root dispatch does not bind the arming between the "
             "immutable and the transient halves of the gate; either a refusal "
             "that costs nothing consumes the owner's arming, or a boot that "
             "refused on the clock, the window, the animation or a journal leaves "
             "it live for the boots after this one")
    # ...and the halves stay apart in the policy, not only in the dispatcher.
    binding_fn = early_root_policy_src.find("public static Decision evaluateArmBinding(")
    binding_end = early_root_policy_src.find(
        "public static Decision evaluateBeforeReadiness(")
    if not (0 < binding_fn < binding_end):
        fail("EarlyRootPolicy no longer separates the immutable half of the gate "
             "from the transient one; the bind has nothing to sit between")
    immutable_body = early_root_policy_src[binding_fn:binding_end]
    for transient in ("PAST_WINDOW,", "BOOT_ALREADY_COMPLETED,",
                      "BOOTANIM_ALREADY_EXITED,", "BOOT_SPENT,",
                      "AUTO_BOOT_SPENT,", "CLOCK_UNAVAILABLE,"):
        if transient in immutable_body:
            fail("the transient refusal %s moved into evaluateArmBinding; it can "
                 "refuse in one boot and allow in the next, so refusing there "
                 "leaves the arming live for a boot the owner never armed"
                 % transient)
    bind_guard = re.search(r"if \(bind != null\) \{(?:[^}]|\}(?!\n        \}))*return false",
                           early_root_dispatch_src, flags=re.S)
    if not bind_guard:
        fail("the early-root dispatch continues after failing to bind the arming to "
             "this boot; an arming that runs without being bound is unbounded")
    claim_guard = re.search(r"if \(claim != null\) \{(?:[^}]|\}(?!\n        \}))*return false",
                            early_root_dispatch_src, flags=re.S)
    if not claim_guard:
        fail("the early-root dispatch continues after failing to claim the arming; "
             "both triggers can pass the gate in one boot and exactly one may run, "
             "so the one that cannot claim is the one that must stop")
    breadcrumb = early_root_dispatch_src.find("val breadcrumb = EarlyRootStore.trace(")
    if breadcrumb < 0 or not re.search(
            r"if \(breadcrumb != null\) \{[^}]*return false",
            early_root_dispatch_src[breadcrumb:], flags=re.S):
        fail("the early-root dispatch continues after a failed entry trace; a "
             "privileged step nobody could have diagnosed is what 3.6.1 forbids")
    if "EarlyRootPolicy.STEP_REFUSED" not in early_root_dispatch_src:
        fail("the early-root dispatch records no durable refusal; a refusal nobody "
             "can read afterwards is indistinguishable from a trigger that never "
             "happened, and on the job trigger the owner just spent a full reboot "
             "on it")
    # An unarmed device must not pay for this path on every boot. The broadcast
    # arrives in every boot of every install, so a breadcrumb written before the
    # arm record is read would mean two fsyncs in /data/system on every boot
    # forever for a cycle nobody armed - instrumentation changing the system it
    # instruments, which is the defect the probe's marker was restructured for.
    read_arm_at = early_root_dispatch_src.find("val armRecord = EarlyRootStore.readArm()")
    crumb_at = early_root_dispatch_src.find("val breadcrumb = EarlyRootStore.trace(")
    if not (0 < read_arm_at < crumb_at):
        fail("the early-root dispatch writes its entry breadcrumb before it has "
             "read the arm record; LOCKED_BOOT_COMPLETED arrives in every boot of "
             "every install, armed or not")
    if "armRecord == null && EarlyRootPolicy.TRIGGER_JOB != trigger" not in \
            early_root_dispatch_src:
        fail("the early-root dispatch no longer leaves an unarmed device alone on "
             "the trigger that fires every boot; an unreadable record must still "
             "trace, an absent one must not")
    if early_root_dispatch_src.count('abandoned("') < 4:
        fail("the early-root dispatch does not check for cancellation at its "
             "boundaries; a run the scheduler took back would still walk into a "
             "dispatch")
    # Exactly one place assembles the policy's inputs. Three copies - two
    # triggers and the service - is three places a field can be left unset, and
    # an unset field is a gate fed nothing, which refuses nothing.
    if "fun inputs(" not in early_root_dispatch_src:
        fail("DfrEarlyRootDispatch no longer owns the input assembly; every caller "
             "building its own is how one of them starts refusing nothing")
    for name, src in (("DfrEarlyRootJobService", early_root_job_src),
                      ("DfrEarlyRootService", early_root_service_src),
                      ("DfrBootReceiver", receiver_code)):
        if "EarlyRootPolicy.Inputs()" in src:
            fail("%s assembles the early-root policy inputs itself instead of using "
                 "the one builder; a field left unset there is a gate fed nothing"
                 % name)
    # --- the stop diagnostics -------------------------------------------
    probe_policy_src_for_gate_check = code_only(
        dfr_source("EarlyBootProbePolicy.java"))
    # Kotlin that needs an Android runtime cannot be unit-tested here
    # (AGENTS.md §5), so the shape is asserted instead.
    #
    # Why this exists: on 2026-10-13, boot f4b7cac2, both jobs were dispatched
    # 22 ms after ThermalStatusRestriction fell from MODERATE to LIGHT, and
    # both were stopped ~4 ms after entry. The records could say WHERE the stop
    # happened and not WHY, and the candidates - device state, a constraint, a
    # preemption, a timeout - have different fixes, so one value for all of
    # them is 3.7's collapse. `params.stopReason` is the API that names it.
    for name, src in (("DfrEarlyRootJobService", early_root_job_src),
                      ("DfrEarlyBootJobService", code_only(early_job_src))):
        if "params.stopReason" not in src:
            fail("%s.onStopJob does not read params.stopReason; the abandonment "
                 "record then says the scheduler stopped us and not which "
                 "pressure did it, and those have different fixes" % name)
        # The ORDER is the whole guarantee. Once `stopped` is true the worker
        # may reach its next boundary and write the record immediately, so a
        # reason assigned afterwards can lose the race and record UNKNOWN.
        reason_at = src.find("token.stopReason = reason")
        thermal_at = src.find("token.stopThermal = thermal")
        flag_at = src.find("token.stopped.set(true)")
        if reason_at < 0 or flag_at < 0:
            fail("%s no longer carries the stop reason onto the run token; the "
                 "worker cannot record what it was never handed" % name)
        elif reason_at > flag_at:
            fail("%s sets the stop flag before the stop reason; the worker can "
                 "then observe the stop and write UNKNOWN for a reason the "
                 "platform did supply" % name)
        # The thermal status is captured AT THE STOP, in onStopJob, and only
        # carried to the boundary. The worker reaches a boundary an unbounded
        # time later - `after_readiness` is on the far side of the readiness
        # sweep - so a reading taken there files a thermal state from one
        # instant against a reason from another, and a transition inside that
        # gap is the event the field exists to catch (AGENTS.md 3.7).
        if thermal_at < 0:
            fail("%s does not capture the thermal status onto the run token in "
                 "onStopJob; a reading taken at the boundary describes a later "
                 "instant than the stop reason beside it" % name)
        elif thermal_at > flag_at:
            fail("%s sets the stop flag before the thermal capture; the worker "
                 "can observe the stop and record UNKNOWN for a reading that "
                 "was available" % name)
        stop_cb = src.find("override fun onStopJob")
        if stop_cb < 0 or not (stop_cb < reason_at and stop_cb < thermal_at):
            fail("%s captures the stop diagnostics outside onStopJob; only that "
                 "callback runs at the instant the scheduler reclaimed the "
                 "execution" % name)
    # --- the arm-and-reboot flow ----------------------------------------
    # MainActivity and RebootRequest need an Android runtime, so the shape is
    # asserted (AGENTS.md §5). The owner's reasons are the invariants.
    main_flow = code_only(dfr_source("MainActivity.kt"))
    reboot_src = code_only(dfr_source("RebootRequest.kt"))

    # ONE arm button. The probe is a checkbox in the dialog now; two buttons
    # were the UI the owner asked to simplify.
    if "btnArmEarlyBootProbe" in main_flow:
        fail("MainActivity still wires a separate Early Boot Probe button; the "
             "owner asked for one arm button with the probe as a dialog option")
    # ...but the probe's state is still reported, or the comparison the
    # checkbox exists for becomes unreadable.
    if "DfrEarlyBootProbe.armState(" not in main_flow:
        fail("the probe's arm state is no longer reported anywhere; it is still "
             "a separate persisted job and the checkbox exists to compare "
             "arming with and without it")

    # The thermal state is read BEFORE the confirmation, so nobody confirms a
    # reboot that will not happen.
    confirm_at = main_flow.find("showArmConfirm(")
    precheck_at = main_flow.find("EarlyRootPolicy.evaluateArmingThermal(")
    if confirm_at < 0 or precheck_at < 0 or precheck_at > confirm_at:
        fail("MainActivity does not pre-check the thermal state before the arm "
             "confirmation; the owner would confirm a reboot the scheduler was "
             "going to veto")

    # THE CENTRAL INVARIANT of this flow: reaching the line after the reboot
    # request means the reboot did NOT happen, and the owner's decision is that
    # nothing stays pending. An arming left live there hands them the
    # ten-second race they asked to be rid of, without saying the clock started.
    arm_then = main_flow.find("private fun armThenReboot(")
    if arm_then < 0:
        fail("the arm-and-reboot flow is gone; the arming would again depend on "
             "reaching the system menu inside REBOOT_WITHIN_MS")
    else:
        end = main_flow.find("\n    }", arm_then)
        body = main_flow[arm_then:end if end > 0 else len(main_flow)]
        req_at = body.find("RebootRequest.requestReboot(")
        dis_at = body.find("DfrEarlyRoot.disarm(")
        if req_at < 0:
            fail("armThenReboot does not request the reboot; the whole point is "
                 "not to depend on the owner reaching the menu in time")
        elif dis_at < 0 or dis_at < req_at:
            fail("armThenReboot does not roll the arming back AFTER the reboot "
                 "request returns; returning from it means the reboot did not "
                 "happen, and leaving the arming live is the ten-second race "
                 "the owner asked to remove - silently")
        if "early_root_reboot_failed_title" not in body:
            fail("armThenReboot does not report the refused reboot in a dialog; "
                 "a log line is what let a failed arming read as a success")
        # A root refusal must not reboot. The probe is observational and must
        # never be the reason a root arming is skipped or kept.
        if "ARM_OUTCOME_ARMED" not in body:
            fail("armThenReboot does not check that the root arming actually "
                 "succeeded before rebooting; it would reboot on a refusal")

    # RebootRequest must treat a NORMAL RETURN as failure. A successful reboot
    # takes the process with it, so a return means the call did nothing - and
    # reporting that as success is exactly the dialog that lies.
    if "returned without rebooting" not in reboot_src:
        fail("RebootRequest no longer treats a normal return from pm.reboot as "
             "a failure; a successful reboot never returns, so a return that "
             "reads as success leaves the owner staring at a dialog that "
             "claimed to reboot")
    # And it must name the exception, because the first physical press is the
    # measurement of whether the uid-level REBOOT argument holds at all.
    if "javaClass.simpleName" not in reboot_src:
        fail("RebootRequest does not name the exception class on failure; that "
             "is the measurement that says whether Shizuku is the next rung")
    # The manifest has to declare the permission it attempts to use.
    with open(os.path.join(ROOT, "app", "src", "main", "AndroidManifest.xml"),
              encoding="utf-8") as f:
        manifest_raw = f.read()
    if "android.permission.REBOOT" not in manifest_raw:
        fail("the manifest does not declare android.permission.REBOOT while "
             "RebootRequest attempts it")
    # The excluded rung stays excluded: RootTransport is gated by 3.6.1 because
    # its first privileged step panicked this kernel.
    if "RootTransport" in reboot_src:
        fail("RebootRequest reaches for RootTransport; that transport is gated "
             "by AGENTS.md 3.6.1 because its first privileged step panicked "
             "this kernel, and a convenience reboot must not drag that in")

    # --- unresolved references in the Kotlin we cannot compile ----------
    #
    # This host has no Kotlin compiler, so every Kotlin change here is verified
    # by reading plus a brace/paren balance - and a balance check cannot see a
    # missing import. On 2026-10-14 that gap shipped: the arming thermal gate
    # added `Log.i(TAG, ...)` to DfrEarlyRoot.kt, which imported neither
    # `android.util.Log` nor defined `TAG`, and the whole offline gate set
    # passed on a file that could not compile.
    #
    # So the two symbols that mistake actually used are checked across every
    # Kotlin source. It is a narrow check and deliberately so: it catches the
    # error that happened, in every file, rather than pretending to be a
    # compiler.
    dfr_dir = os.path.join(ROOT, "app", "src", "main", "java", "com",
                           "polygraphene", "df", "reroot")
    kt_sources = sorted(
        os.path.join(dfr_dir, n) for n in os.listdir(dfr_dir) if n.endswith(".kt")
    )
    if not kt_sources:
        fail("no DFReroot Kotlin sources found; this check would silently "
             "guard nothing")
    for src_path in kt_sources:
        with open(src_path, encoding="utf-8") as f:
            body = code_only(f.read())
        name = rel(src_path)
        if re.search(r"\bLog\.[deiwv]\s*\(", body) \
                and "import android.util.Log" not in body:
            fail("%s calls Log.* without importing android.util.Log; this host "
                 "cannot compile Kotlin, so nothing else here would catch it"
                 % name)
        if re.search(r"\bLog\.[deiwv]\s*\(\s*TAG\b", body) \
                and not re.search(r"\bTAG\s*=", body):
            fail("%s passes TAG to Log.* without defining it; a brace balance "
                 "cannot see an unresolved reference" % name)

    # --- the arming outcome is a modal ----------------------------------
    # MainActivity needs an Android runtime and cannot be unit-tested here
    # (AGENTS.md §5), so the shape is asserted instead.
    #
    # Why it exists: `[*] EARLY_ROOT_ARMED` and `[x] EARLY_ROOT_NOT_ARMED`
    # differ by a few characters in a pane that scrolls, so a refusal was being
    # read as a success and a reboot spent on a job that was never scheduled.
    # Not arming is not the expected behaviour and must not look like it.
    main_src = code_only(dfr_source("MainActivity.kt"))
    if "showArmOutcome(" not in main_src:
        fail("MainActivity no longer shows the arming outcome as a dialog; the "
             "log line alone is what let a refusal read as a success")
    # It is called from the arm handler, after the arm() call - a dialog that
    # is never reached is the same as not having one.
    arm_at = main_src.find("DfrEarlyRoot.arm(")
    show_at = main_src.find("showArmOutcome(line)")
    if arm_at < 0 or show_at < 0 or show_at < arm_at:
        fail("the arming outcome dialog is not shown from the arm handler after "
             "arm() returns; the owner would be back to reading the log")
    # The classification is the host-tested policy, not a string test in an
    # Activity nobody can test here.
    if "EarlyRootPolicy.armOutcome(" not in main_src:
        fail("MainActivity classifies the arming outcome itself instead of "
             "using the host-tested policy; a string test in an untestable "
             "Activity is how 'armed' gets painted over a refusal")
    # BOTH outcomes get a dialog. A modal that only appears on failure trains
    # the reader to ignore its absence.
    for res in ("early_root_arm_ok_title", "early_root_arm_refused_title",
                "early_root_arm_unknown_title"):
        if res not in main_src:
            fail("MainActivity does not reference R.string.%s; both arming "
                 "outcomes and the unaccountable one each need their own, or "
                 "the dialog stops distinguishing them" % res)
    # And the unrecognised branch must NOT be the success title: a line this
    # build cannot account for reports NOT ARMED rather than guessing.
    else_at = main_src.find("else -> R.string.early_root_arm_unknown_title")
    if else_at < 0:
        fail("the unrecognised arming outcome no longer falls through to the "
             "NOT ARMED title; painting 'armed' over an unknown outcome is "
             "exactly the confusion this dialog removes")

    # --- the arming-time thermal gate -----------------------------------
    # The owner's ask: do not spend a reboot on a callback the scheduler will
    # veto. ThermalStatusRestriction restricts PRIORITY_DEFAULT outright from
    # MODERATE up, so the arming is where that is cheap to refuse.
    early_root_src = code_only(dfr_source("DfrEarlyRoot.kt"))
    if "EarlyRootPolicy.evaluateArmingThermal(" not in early_root_src:
        fail("DfrEarlyRoot no longer consults the arming thermal gate; the owner "
             "spends a whole reboot discovering what one read answers")
    # It has to come BEFORE the first durable write, or a refusal leaves a
    # rewritten record behind and the message that says otherwise is false.
    gate_at = early_root_src.find("EarlyRootPolicy.evaluateArmingThermal(")
    incident_at = early_root_src.find("recordPendingIncident(")
    sched_at = early_root_src.find("scheduler.schedule(")
    if incident_at >= 0 and gate_at > incident_at:
        fail("the arming thermal gate runs after recordPendingIncident; a "
             "refusal would then leave a durable write behind, and the refusal "
             "message says nothing was changed")
    if sched_at >= 0 and gate_at > sched_at:
        fail("the arming thermal gate runs after the job is scheduled; the "
             "point is to refuse before anything exists")
    # And the readings reach the record, which is the before-the-reboot half of
    # the pairing the threshold has to be derived from.
    for key in ("armed_thermal_status", "armed_thermal_headroom"):
        if key not in code_only(dfr_source("EarlyRootPolicy.java")):
            fail("the arm record no longer carries %r; without it the 0.85 "
                 "headroom limit can never stop being a guess" % key)
    # Pinned on the CALL SHAPE, not on a constant's name: an earlier version of
    # this guard searched for "ARM_OPTIONAL_KEYS" and a mutation that merely
    # renamed the constant still satisfied it by substring.
    if "parse(record, ARM_KEYS, ARM_OPTIONAL_KEYS)" not in code_only(
            dfr_source("EarlyRootPolicy.java")):
        fail("parseArm no longer reads the thermal fields as OPTIONAL; a record "
             "written before they existed would read as malformed, turning a "
             "precise BUILD_MISMATCH after an app upgrade into a bare "
             "NOT_ARMED")
    # A thermal refusal must REPORT any surviving arming.
    #
    # The gate returns before the job is inspected and before any record is
    # touched, which is what makes "this attempt changed nothing" true - but a
    # reader takes NOT ARMED to mean the DEVICE is not armed. Arm while cool,
    # wait, press Arm once it has heated, and the earlier job and arm record are
    # still live: the dialog would say "do not reboot" over an armed device,
    # which is the owner's own complaint inverted and the more dangerous
    # direction. Codex caught it on PR #70.
    thermal_refusal_at = early_root_src.find("if (!thermal.allow)")
    if thermal_refusal_at < 0:
        fail("the arming thermal refusal branch is gone; this guard cannot "
             "speak for what it reports")
    else:
        branch_end = early_root_src.find("\n        }", thermal_refusal_at)
        branch = early_root_src[thermal_refusal_at:
                                branch_end if branch_end > 0 else len(early_root_src)]
        if "armState(" not in branch:
            fail("the arming thermal refusal does not report the prior arming "
                 "state; it would say NOT ARMED over a device that is still "
                 "armed and will consume the next reboot")
        if "ARM_NO_RECORD" not in branch:
            fail("the arming thermal refusal does not distinguish 'no previous "
                 "arming' from one that survived; collapsing those is what "
                 "makes the message a lie in one of the two cases")
        # And it must not CANCEL as a side effect: that would make its own
        # "changed no record" sentence false and would throw away an arming the
        # owner deliberately made. disarm() is an action they take.
        for forbidden in ("disarm(", "cancelOwned(", "deleteArm("):
            if forbidden in branch:
                fail("the arming thermal refusal calls %s; a read-only check "
                     "must not destroy a valid arming as a side effect, and it "
                     "claims in the same message that it changed nothing"
                     % forbidden)

    # THE ASYMMETRY, pinned in both directions because it is the one place this
    # file deliberately allows on missing evidence. This gate protects a reboot,
    # not the device; a diagnostic that cannot read itself must not withhold a
    # capability (3.6.1), and every gate that protects the device still runs at
    # the callback. A future edit in EITHER direction should have to say so.
    policy_src = code_only(dfr_source("EarlyRootPolicy.java"))
    if "THERMAL_UNREADABLE" not in policy_src:
        fail("the unreadable thermal verdict is gone; an unobtainable reading "
             "must be recorded as such, never folded into a pass")
    # Pinned on the exact return, because the function also returns
    # `new Decision(true, THERMAL_OK, ...)` - so looking for "new Decision(true"
    # anywhere in the body passes whatever the unreadable branch does. An
    # earlier version of this guard made that mistake and caught nothing.
    if "new Decision(true, THERMAL_UNREADABLE" not in policy_src:
        fail("evaluateArmingThermal no longer ALLOWS on an unreadable reading; "
             "that turns a failed diagnostic into a permanent refusal of the "
             "capability, which is the 3.6.1 failure this gate must not become "
             "- it protects a reboot, not the device")
    # There must be NO matching check at the callback: if the scheduler
    # dispatched us the restriction was not in force, so a check there could
    # only withhold a run the platform already permitted.
    if "evaluateArmingThermal" in code_only(dfr_source("DfrEarlyRootDispatch.kt")):
        fail("the dispatch consults the arming thermal gate; a dispatched "
             "callback proves the restriction was not in force, so a check "
             "there can only withhold a run that was going to work")

    # --- the timeline collector's entry metric ---------------------------
    # Guarded here because the defect was a DELETION, not wrong logic, and a
    # deletion is invisible to a test that supplies the deleted value itself.
    # On PR #78 a line-range replacement moved the budget to /proc and removed
    # every assignment to TRACE_DISPATCH while leaving the `-v tracedisp=`
    # pass in place, so the entry-to-AMS measurement - the number that PR
    # existed to produce - read NOT COMPUTABLE on every boot. The awk had been
    # tested with `-v tracedisp=17847` fed in by hand: an input the script
    # does not produce. Fourth time in this family (see the -b all and
    # -v threadtime comments in the collector itself).
    collector = os.path.join(ROOT, "tools", "earlyroot_collect_timeline.sh")
    if os.path.exists(collector):
        with open(collector, "r", encoding="utf-8") as fh:
            coll = fh.read()
        assigns = re.search(r"(?m)^[ \t]*TRACE_DISPATCH=", coll)
        if "tracedisp=" in coll and not assigns:
            fail("earlyroot_collect_timeline.sh passes tracedisp= to awk with no "
                 "assignment to TRACE_DISPATCH anywhere: the entry metric reads "
                 "NOT COMPUTABLE on every boot (PR #78)")
        # Codex review on PR #78 found both of the next two guards defeatable
        # by a COMMENT. Each searched the whole file for a token, and each
        # token also appears in the prose above the code it guards: the two
        # entry-step names at lines 216-217 and in the awk filter, `NF-1` in
        # the field-layout comment. So the executable line could change to the
        # wrong value and the audit would still pass on the comment's copy.
        #
        # Same defect family as the XX_TRACE_DISPATCH= substring that passed an
        # earlier mutation test in this file: a guard that matches text
        # anywhere is not a guard on the text that runs. Both now match the
        # shape that EXECUTES.
        #
        # The mapping is validated arm by arm rather than by token presence,
        # because the failure Codex described is a mapping error - the `*)` arm
        # selecting the job step - in which both tokens are still present and
        # only broadcast-claimed boots read NOT COMPUTABLE.
        case_m = re.search(
            r"(?s)case\s+\"\$\{TRACE_CLAIM_TRIGGER:-\}\"\s+in(.*?)\besac\b", coll)
        if "tracedisp=" in coll and case_m is None:
            fail("earlyroot_collect_timeline.sh passes tracedisp= to awk but no "
                 "`case \"${TRACE_CLAIM_TRIGGER:-}\" in` block selects the entry "
                 "step; the two triggers write different step names "
                 "(AGENTS.md 3.11) and the metric is empty on whichever is not "
                 "named")
        if case_m is not None:
            arms = case_m.group(1)
            for pattern, why in (
                (r"(?m)^\s*job\)\s*TRACE_ENTRY_STEP=EARLY_ROOT_JOB_ENTERED\s*;;",
                 "the `job)` arm must select EARLY_ROOT_JOB_ENTERED"),
                (r"(?m)^\s*\*\)\s*TRACE_ENTRY_STEP=EARLY_ROOT_TRIGGER_ENTERED\s*;;",
                 "the `*)` arm must select EARLY_ROOT_TRIGGER_ENTERED"),
                (r'(?m)^\s*""\)\s*TRACE_ENTRY_STEP=\s*;;',
                 'the `""` arm must select NOTHING, so a boot with no claim '
                 'reports <no claim recorded> rather than a wrong step'),
            ):
                if not re.search(pattern, arms):
                    fail("earlyroot_collect_timeline.sh entry-step mapping is "
                         "wrong: %s. A mapping error leaves both names present "
                         "in the file, so only the arm itself can be checked "
                         "(Codex, PR #78)" % why)

        # Full-line comments only: stripping a trailing # from shell is unsafe
        # (it can sit inside a string), and the comment that defeated this
        # guard was a whole line. The regex then matches the AWK ASSIGNMENT,
        # not the token, so `k = $NF` fails here whatever the prose says.
        coll_code = re.sub(r"(?m)^[ \t]*#.*$", "", coll)
        if ("enhanced_boot_stat" in coll
                and not re.search(r"\bk\s*=\s*\$\(NF-1\)", coll_code)):
            fail("the collector parses /proc/enhanced_boot_stat without "
                 "`k = $(NF-1)`: a milestone line carries time/ktime/delta "
                 "while a `Took Nms by` line carries only time/ktime, so $NF "
                 "reads the delta on one shape and the ktime on the other")

    # --- the readiness TRIGGER (2026-10-14) ------------------------------
    # The clock stopped choosing the moment. Boot cea5208c measured what that
    # cost: the hop's target process was bound at 14011 ms (am_proc_bound, i.e.
    # attachApplication) and the callback arrived at 15354 ms, so 1343 ms went
    # to setMinimumLatency waiting for something already present. The floor is
    # structural - boot_progress_ams_ready was 13312 ms and AMS starts no app
    # process before it - so the wait, not the constant, has to find it.
    #
    # Five properties. Each one is the difference between a bounded probe and
    # the unbounded operation AGENTS.md 3.6.1 forbids wearing a probe's name.
    dispatch_src = code_only(dfr_source("DfrEarlyRootDispatch.kt"))
    policy_src = code_only(dfr_source("EarlyRootPolicy.java"))

    # (1) The loop exists and every decision in it is the PURE function. Kotlin
    #     cannot be unit-tested here (AGENTS.md 5), so a loop carrying its own
    #     judgement would be judgement nothing tests.
    if "EarlyRootPolicy.readinessWait(" not in dispatch_src:
        fail("the dispatch no longer consults EarlyRootPolicy.readinessWait; "
             "readiness is back to being sampled once at whatever instant the "
             "clock handed us, which cost 1343 ms in boot cea5208c")
    if "EarlyRootPolicy.WAIT_AGAIN ==" not in dispatch_src:
        fail("the readiness loop no longer continues on the policy's WAIT_AGAIN; "
             "a loop condition written in Kotlin is a decision no host test "
             "can reach")

    # (2) The wait CANNOT permit. evaluate() stays the sole authority, and the
    #     loop must not acquire a path that proceeds on anything but the gate.
    #     A wait that promoted a PARTIAL sweep would be absence-as-permission
    #     (AGENTS.md 2) - the one thing this repository exists to prevent.
    if "EarlyRootPolicy.evaluate(" not in dispatch_src:
        fail("the dispatch no longer runs EarlyRootPolicy.evaluate after the "
             "readiness wait; the wait would then be the thing that permits")
    wait_at = dispatch_src.find("EarlyRootPolicy.readinessWait(")
    eval_at = dispatch_src.find("EarlyRootPolicy.evaluate(")
    if wait_at >= 0 and eval_at >= 0 and wait_at > eval_at:
        fail("the readiness wait runs after EarlyRootPolicy.evaluate; the gate "
             "would then judge a sweep taken before the wait could improve it")
    if "NETWORKSTACK_READY" in dispatch_src:
        fail("the dispatch names NETWORKSTACK_READY itself; readiness is "
             "compared in exactly one place (AGENTS.md 3.2) and a second "
             "comparison in Kotlin is one no host test can falsify")

    # (3) The wait is BOUNDED, by an ABSOLUTE elapsed bound rather than a
    #     duration. A duration from a variable callback instant bounds the one
    #     quantity this path races - the animation - differently every boot.
    if "READINESS_WAIT_DEADLINE_MS" not in policy_src:
        fail("the readiness wait lost its deadline; an unbounded wait inside "
             "system_server during boot is an operation, not a probe (3.6.1)")
    if "nowMs >= READINESS_WAIT_DEADLINE_MS" not in policy_src:
        fail("readinessWait no longer compares the clock against the deadline "
             "as an absolute elapsed bound; a duration measured from the "
             "callback gives a different cutoff in every boot")
    if "nowMs <= 0L" not in policy_src:
        fail("readinessWait no longer stops on an unreadable clock; a wait "
             "whose deadline cannot be evaluated is unbounded")
    # And the three non-expiry abort causes keep their own names. Codex's P2 on
    # PR #74: an unreadable clock reported as WAIT_EXPIRED tells the operator
    # the deadline passed with readiness absent - a claim about the BOOT - when
    # a clock read failed in this process. AGENTS.md 3.7 names this pair
    # exactly: a primary lookup being unavailable vs the lookup as a whole
    # failing. The handoff sends the two readings to different places.
    if "return WAIT_CLOCK_UNAVAILABLE;" not in policy_src:
        fail("an unreadable clock no longer has its own wait outcome; reported "
             "as an expiry it manufactures evidence about the boot out of a "
             "clock failure in this process (3.7)")
    if "WAIT_INTERRUPTED" not in dispatch_src:
        fail("the interrupted wait no longer has its own outcome; something "
             "asking this thread to stop says nothing about whether readiness "
             "was coming, and the handoff reads an expiry as a slow boot")
    if "waitOutcome = EarlyRootPolicy.WAIT_EXPIRED" in dispatch_src:
        fail("the dispatch assigns WAIT_EXPIRED itself; only readinessWait may "
             "conclude the deadline passed, and a caller that does it is the "
             "collapse Codex caught on PR #74")

    # (4) The loop can be reclaimed mid-wait. This is now the one place the
    #     dispatch can spend seconds, so the scheduler taking the execution
    #     back must not find us still polling.
    if 'abandoned("readiness_wait")' not in dispatch_src:
        fail("the readiness loop does not check `abandoned` on each iteration; "
             "the dispatch can now spend seconds there and a reclaimed "
             "execution would keep sweeping AMS during boot")

    # (5) The measurement survives BOTH outcomes. "readiness never arrived" and
    #     "readiness arrived and something else refused" send the next physical
    #     run to different places (3.7), and the refusal trace is the only
    #     record that outlives this firmware's log buffer.
    if "formatReadinessWait(" not in policy_src:
        fail("the wait measurement is gone; the instant readiness flips is the "
             "structural floor this path has been guessing at")
    if dispatch_src.count("EarlyRootPolicy.formatReadinessWait(") < 2:
        fail("the wait measurement is recorded on fewer than both paths; an "
             "expired wait is the case the owner most needs to read and it "
             "refuses before the readiness step is ever written")

    # (6) The wait refuses to be the thing that blocks. This code is hosted in
    #     system_server, so seconds of Thread.sleep on the main looper would
    #     block the framework that is still booting and a Watchdog kill takes
    #     the boot with it - 3.6.1 on the one process whose death is not a
    #     refusal. Both triggers use a worker today; the guard is here because
    #     the regression is a refactor two files away, not an edit in the loop.
    if "Looper.getMainLooper()" not in dispatch_src:
        fail("the readiness wait no longer checks whether this thread may be "
             "blocked; a caller refactored onto the main looper would sleep "
             "seconds inside system_server during boot")
    if "while (mayBlock &&" not in dispatch_src:
        fail("the readiness loop no longer requires permission to block; the "
             "main-looper check is computed and then ignored, which is worse "
             "than not having it")
    if "WAIT_NOT_PERMITTED" not in dispatch_src or (
            "WAIT_NOT_PERMITTED" not in policy_src):
        fail("a wait that was not permitted to run reports as something else; "
             "'we never looked again' is a defect in our threading and "
             "'readiness never came' is a fact about the boot (3.7)")
    if "Thread.sleep" in dispatch_src and "mayBlock" not in dispatch_src[
            :dispatch_src.find("Thread.sleep")]:
        fail("Thread.sleep is reachable in the dispatch without the "
             "may-this-thread-block decision preceding it")

    # --- the chained soft reboot (2026-10-15, owner decision) -------------
    # The owner asked for the soft reboot to run as soon as post-root finishes,
    # at whatever moment that falls. Kotlin cannot be unit-tested here
    # (AGENTS.md 5), and this path hands a boot to a userspace teardown that has
    # two unexplained firmware reboots behind it, so each property that keeps it
    # honest is asserted statically. Five, because the chain is one edit away
    # from being either unguarded or silently dead.
    service_src = code_only(dfr_source("DfrEarlyRootService.kt"))

    # (1) The decision is the PURE function, not an `if` in the service. The
    #     negatives live in EarlyRootPolicyTest; a condition inlined here would
    #     be judgement nothing tests.
    if "EarlyRootPolicy.chainSoftReboot(" not in service_src:
        fail("DfrEarlyRootService no longer calls EarlyRootPolicy.chainSoftReboot; "
             "the chained soft reboot's decision belongs in the pure, "
             "host-tested unit and not in the service (AGENTS.md 5)")

    # (0) EVERY component the early path reaches must be directBootAware, and
    #     this check exists because its absence was the THIRD thing that
    #     silently killed the chained soft reboot - after the arm-boot binding
    #     and the unregistered trace step.
    #
    #     While the user is locked, PMS resolves only direct-boot-aware
    #     components, so a sendBroadcast naming a non-aware receiver matches
    #     nothing and is dropped WITH NO ERROR. The early chain runs pre-unlock
    #     (`user_unlocked=0`, measured at the callback in three consecutive
    #     boots), so the handoff went nowhere. Every other component on that
    #     path already carried the attribute; the receiver did not, because
    #     until this change it was only ever reached by a notification tap,
    #     which happens after unlock.
    #
    #     Checked per component rather than as one grep, so the failure names
    #     which one is missing it, and listed explicitly rather than derived
    #     from the source: a component the early path stops reaching should drop
    #     off this list by a deliberate edit, not by a regex no longer matching.
    for component in (".DfrBootReceiver", ".DfrAutoRootService",
                      ".DfrEarlyBootJobService", ".DfrEarlyRootJobService",
                      ".DfrEarlyRootService", ".DfrSoftRebootReceiver"):
        decl = re.search(
            r'android:name="' + re.escape(component) + r'"((?:(?!/>|>)[\s\S])*)',
            manifest)
        if decl is None:
            fail("AndroidManifest.xml does not declare %s; the early path "
                 "reaches it, and an undeclared component receives nothing"
                 % component)
        elif 'android:directBootAware="true"' not in decl.group(1):
            fail("%s is not android:directBootAware; the early chain runs with "
                 "the user locked (user_unlocked=0, measured), and PMS resolves "
                 "only direct-boot-aware components then - a broadcast or start "
                 "naming it is dropped with no error" % component)

    # (1a) It feeds the decision the CYCLE, not only the arm record. The first
    #      version compared the current boot to the arm record's armed_boot_id
    #      and required equality - but ARM_SAME_BOOT refuses a run whose
    #      callback fired in the armed boot, so a real run's boots always
    #      differ and the feature was dead on arrival while its own test
    #      passed on an input production cannot produce. The cycle is the half
    #      written in the RUN boot, so without it there is nothing to place the
    #      authorisation in this boot.
    if "EarlyRootStore.readCycle()" not in service_src:
        fail("the chained soft reboot does not read the cycle record; the arm "
             "record alone was written in the PREVIOUS boot, and binding to it "
             "is what made this dead on arrival (Codex, PR #81)")
    if "arm.armedBootId" in policy_src[policy_src.find("chainSoftReboot("):
                                       policy_src.find("formatJournal(")]:
        fail("chainSoftReboot compares the current boot to armed_boot_id again; "
             "ARM_SAME_BOOT refuses exactly that equality, so this returns a "
             "foreign refusal on every real run")

    # (1b) The decision runs on BOTH the success and the failure path, or
    #      CHAIN_SOFT_REBOOT_ROOT_INCOMPLETE is modelled, tested and dead, and
    #      a failed run records nothing about why it did not hand over. A dead
    #      branch reads as a check (AGENTS.md 5).
    #      Checked by INDENTATION, not by a brace-matched region. The first
    #      version of this guard used `if \(result\.success\)[^}]*\{[^}]*<call>`
    #      and passed its own mutation: the success branch's log line contains
    #      `${result.liveSelinux}`, so `[^}]*` stops at that template's closing
    #      brace before reaching the call. Kotlin string templates make brace
    #      counting unreliable here; the call's own indentation does not lie.
    chain_call = "chainSoftReboot(context, bootId, result.success)"
    if not re.search(r"(?m)^        " + re.escape(chain_call) + r"\s*$", service_src):
        fail("the chained soft reboot is no longer invoked at the terminal "
             "block's own level with the run's own verdict; calling it only "
             "under result.success makes ROOT_INCOMPLETE unreachable in "
             "production (Codex, PR #81)")
    if re.search(r"(?m)^ {12,}chainSoftReboot\(", service_src):
        fail("the chained soft reboot is invoked nested inside a branch; its "
             "root-incomplete outcome and trace step are then dead, and the "
             "step's contract is that it is written on EVERY outcome")

    # (2) It dispatches through the RECEIVER, never by reaching into the
    #     soft-reboot sequence itself. That is 3.2 satisfied by construction:
    #     DfrSoftRebootReceiver re-derives the post-root record, the per-boot
    #     lock, the ksud digest, the transport_fix marker and the firmware
    #     boot-health verdict, so this path cannot be the one that forgets a
    #     gate. A direct call to SoftRebootPolicy or RootTransport from here
    #     would be a second copy of that sequence.
    if "DfrSoftRebootReceiver.ACTION_APPLY_MODULES" not in service_src:
        fail("the early chain no longer hands the soft reboot to "
             "DfrSoftRebootReceiver.ACTION_APPLY_MODULES; a second path into "
             "the teardown is a second place a gate can be forgotten (3.2)")
    for banned in ("SoftRebootPolicy.evaluate", "RootTransport.prepare",
                   "SoftRebootHealth.recordPreExec"):
        if banned in service_src:
            fail("DfrEarlyRootService references %r; the chained soft reboot "
                 "must go through the receiver that re-derives every gate, not "
                 "re-implement any part of it (3.2)" % banned)

    # (3) The trace precedes the dispatch, and is written on EVERY outcome.
    #     3.11's rule, and the reason is specific: a boot that does not come
    #     back has to say whether the box was ticked, whether the arming was
    #     foreign, or whether the broadcast went out. A trace only on the
    #     interesting path cannot tell "not asked for" from "died before
    #     deciding".
    if "EarlyRootPolicy.STEP_CHAIN_SOFT_REBOOT" not in service_src:
        fail("the chained soft reboot no longer writes its own trace step; "
             "every boundary that can refuse gets one (3.11)")
    chain_fn = service_src[service_src.find("private fun chainSoftReboot"):]
    if chain_fn:
        chain_fn = chain_fn[:chain_fn.find("\n    private fun ", 1)] or chain_fn
        trace_at = chain_fn.find("STEP_CHAIN_SOFT_REBOOT")
        send_at = chain_fn.find("sendBroadcast")
        if trace_at < 0 or send_at < 0 or trace_at > send_at:
            fail("the chained soft reboot broadcasts before tracing, or does "
                 "not trace at all; the record of having asked must exist "
                 "before the asking (3.6.1, same rule as traceSoftReboot)")
        # (3a) And a trace that cannot be WRITTEN refuses the step - 3.11
        #      verbatim. An earlier version logged the failure and broadcast
        #      anyway, reasoning that the receiver's own traceSoftReboot covers
        #      the privileged steps. It does not cover this one: that record
        #      says what the teardown did, this one says whether this boundary
        #      authorised the handoff, and in a boot that does not come back
        #      they are different questions.
        if not re.search(r"val\s+\w*[Ff]ailure\s*=\s*trace\(", chain_fn):
            fail("the chained soft reboot discards trace()'s return; a trace "
                 "that cannot be written must refuse the step it announces "
                 "(3.11), not be logged and stepped over")
        gate = re.search(r"if \(\w*[Ff]ailure != null\)\s*\{", chain_fn)
        if not gate or gate.start() > send_at:
            fail("the chained soft reboot does not return on a failed trace "
                 "before broadcasting; a teardown with no pre-operation "
                 "attribution is absence-as-permission (2)")

    # (4) It reads NO boot phase. This is the owner's decision of 2026-10-15,
    #     stated as a property so a later "just check boot_completed first"
    #     cannot land quietly: the goal of landing inside the animation was
    #     measured and is not reachable, and a phase condition here would
    #     silently restore the manual tap the chain exists to remove.
    if chain_fn:
        for phase_token in ("sys.boot_completed", "LOCKED_BOOT_COMPLETED",
                            "isDeviceLocked", "isKeyguardLocked",
                            "bootState("):
            if phase_token in chain_fn:
                fail("the chained soft reboot reads %r; the owner's decision is "
                     "that it runs when post-root finishes at WHATEVER moment "
                     "that is, so a boot-phase condition here is a change of "
                     "that decision and not a hardening" % phase_token)

    # (5) The authorisation is per-arming and spent with it, never a standing
    #     switch (3.11). It rides the arm record as an OPTIONAL key so a build
    #     that never wrote it still arms and still roots - required to act,
    #     never to parse, the same shape as transport_fix in 3.6.1.
    if '"armed_soft_reboot"' not in policy_src:
        fail("EarlyRootPolicy no longer carries armed_soft_reboot; the "
             "chained soft reboot's authorisation must ride the per-arming "
             "record rather than a persistent preference (3.11)")
    arm_optional = re.search(r"ARM_OPTIONAL_KEYS = Set\.of\(([^)]*)\)", policy_src)
    if not arm_optional or "armed_soft_reboot" not in arm_optional.group(1):
        fail("armed_soft_reboot is not in ARM_OPTIONAL_KEYS; making it required "
             "would refuse every arm record written by a build without it, "
             "which breaks arming on any device that has not rebuilt (3.6.1)")

    # --- the deferred retry of that handoff (owner's P1 on PR #81) --------
    # The chain hands off the instant post-root finishes; the receiver then
    # re-derives the firmware's boot-health handshake, which needs
    # sys.boot_completed, dev.bootcomplete, dev.platform_bootcomplete, a running
    # zygote AND both init.svc.bootchecker* reading stopped. The chain finishes
    # in the low tens of seconds and a bootchecker process of this firmware was
    # measured alive across ktime 27 s, so PENDING there is the likely case -
    # and the outcome was root PASS with the modules never applied, with nothing
    # that would ever ask again.
    #
    # This is the one place in this feature that DOES key on a boot phase, and
    # that is a difference in kind rather than a softening: the CHAIN still
    # reads none (guard (4) above), and what this adds is a strictly later
    # moment at which the same receiver, with the same gates, is asked once
    # more. The gates are untouched - 3.6 reserves removing the boot-health
    # refusal for the owner, and it came out of two physical rollbacks.
    #
    # Kotlin cannot be unit-tested here, so each property is static. The
    # negatives of the DECISION are in EarlyRootPolicyTest.
    boot_receiver_code = code_only(boot_receiver_src)

    # (R1) The decision is the pure function. An `if` here would be judgement
    #      nothing tests, and this one decides whether to tear userspace down.
    if "EarlyRootPolicy.chainSoftRebootRetry(" not in boot_receiver_code:
        fail("DfrBootReceiver no longer calls EarlyRootPolicy.chainSoftRebootRetry; "
             "the deferred soft-reboot handoff's decision belongs in the pure, "
             "host-tested unit (AGENTS.md 5), and its P1 is that a boot whose "
             "handshake was PENDING at post-root never asked again")

    # (R2) BOOT_COMPLETED only. Convergence requires sys.boot_completed=1 among
    #      other things, and that property is not set at locked boot - a retry
    #      there could only reproduce the refusal it exists to outlive.
    retry_guard = re.search(
        r"if \(action == Intent\.ACTION_BOOT_COMPLETED\) \{\s+"
        r"retrySoftRebootChain\(", boot_receiver_code)
    if not retry_guard:
        fail("the deferred soft-reboot retry is not gated on BOOT_COMPLETED "
             "alone; at LOCKED_BOOT_COMPLETED sys.boot_completed is still 0, so "
             "the boot-health handshake cannot converge and the retry would "
             "spend its one attempt reproducing the refusal")

    retry_fn = boot_receiver_code[
        boot_receiver_code.find("private fun retrySoftRebootChain"):]
    if not retry_fn:
        fail("DfrBootReceiver.retrySoftRebootChain is gone; the deferred handoff "
             "has no carrier")
    else:
        retry_fn = retry_fn[:retry_fn.find("\n    private fun ", 1)] or retry_fn

        # (R3) It hands off to the RECEIVER, never re-implementing the teardown.
        #      Same reasoning as the chain's (2): one soft-reboot sequence, so
        #      this path cannot be the one that forgets a gate (3.2).
        if "DfrSoftRebootReceiver.ACTION_APPLY_MODULES" not in retry_fn:
            fail("the deferred retry no longer hands the soft reboot to "
                 "DfrSoftRebootReceiver.ACTION_APPLY_MODULES; a second path into "
                 "the teardown is a second place a gate can be forgotten (3.2)")
        for banned in ("SoftRebootPolicy.evaluate", "SoftRebootPolicy.precheck",
                       "RootTransport.prepare", "SoftRebootHealth.recordPreExec",
                       "AutoRootStore.claimSoftReboot"):
            if banned in retry_fn:
                fail("DfrBootReceiver's deferred retry references %r; it must ask "
                     "the receiver that re-derives every gate - boot-health "
                     "included - and re-implement no part of it (3.2)" % banned)

        # (R4) The trace precedes the broadcast AND refuses it when it cannot be
        #      written. Here that line is not only the pre-operation record
        #      (3.6.1) but the ONE-SHOT itself: BOOT_COMPLETED is re-delivered
        #      under the same boot_id by every framework restart - including the
        #      one a successful soft reboot performs - so a retry that cannot
        #      record itself has no bound on how often it re-asks.
        if "EarlyRootPolicy.STEP_CHAIN_SOFT_REBOOT_RETRY" not in retry_fn:
            fail("the deferred retry no longer writes its own trace step; it is "
                 "both the pre-operation record and the one-shot (3.11)")
        if "EarlyRootPolicy.STEP_CHAIN_SOFT_REBOOT," in retry_fn:
            fail("the deferred retry writes the CHAIN's step instead of its own; "
                 "one name for both moments makes the retry re-authorise itself "
                 "on every re-delivered BOOT_COMPLETED, and collapses two "
                 "different firmware states into one reading (3.7)")
        retry_trace_at = retry_fn.find("STEP_CHAIN_SOFT_REBOOT_RETRY")
        retry_send_at = retry_fn.find("sendBroadcast")
        if retry_send_at < 0 or retry_trace_at > retry_send_at:
            fail("the deferred retry broadcasts before tracing, or does not "
                 "broadcast at all; the record of having asked must exist before "
                 "the asking (3.6.1), and here it is also the one-shot")
        retry_gate = re.search(r"if \(\w*[Ff]ailure != null\)\s*\{", retry_fn)
        if not retry_gate or retry_gate.start() > retry_send_at:
            fail("the deferred retry does not return on a failed trace before "
                 "broadcasting; without that line there is no bound on how many "
                 "times a re-delivered BOOT_COMPLETED can re-ask")

        # (R4a) And it waits for the firmware before asking, bounded, with the
        #      timeout as its own recorded outcome. BOOT_COMPLETED is NOT when
        #      the handshake converges: measured 2026-10-18, chain done at
        #      20.347 s, converged at 68.728 s, with BOOT_COMPLETED around 42 s
        #      on this device. A retry pinned to the broadcast refuses for the
        #      same reason the chain's own handoff did, which is a feature that
        #      cannot fire - the fourth time in this repository that a path
        #      shipped inert.
        if "awaitBootHealth(" not in retry_fn:
            fail("the deferred retry asks the receiver without waiting for the "
                 "firmware's boot-health handshake; it was measured converging "
                 "at 68.728 s in a boot whose BOOT_COMPLETED is ~42 s, so this "
                 "is a retry that refuses for the very reason it exists")
        wait_at = retry_fn.find("awaitBootHealth(")
        if wait_at > retry_send_at:
            fail("the deferred retry broadcasts before waiting for the "
                 "handshake, so the wait cannot change the outcome")
        if "if (!waited.converged)" not in retry_fn:
            fail("the deferred retry does not branch on the wait's result; a "
                 "timeout that falls through to the broadcast asks for a "
                 "teardown in a boot the firmware does not consider complete")
        timeout_at = retry_fn.find("if (!waited.converged)")
        if timeout_at < 0 or timeout_at > retry_send_at:
            fail("the deferred retry's timeout branch does not return before "
                 "the broadcast")
        # ...and the wait is bounded and reads the handshake rather than a clock
        # alone. An unbounded wait inside system_server is a thread that never
        # ends; a wait that does not read the verdict is a sleep pretending to
        # be a condition.
        wait_fn = boot_receiver_code[
            boot_receiver_code.find("private fun awaitBootHealth"):]
        wait_fn = wait_fn[:wait_fn.find("\n    private fun ", 1)] or wait_fn
        for required in ("RETRY_HEALTH_BUDGET_MS", "SoftRebootHealth.liveVerdict(",
                         "SoftRebootHealthPolicy.permitsDispatch("):
            if required not in wait_fn:
                fail("the deferred retry's wait lost %r; a wait that is "
                     "unbounded, or that does not read the same handshake the "
                     "receiver gates on, is not the condition it claims to be"
                     % required)
        # EXACTLY ONE converged exit, and it is the one the handshake guards.
        # Checked by counting rather than by presence: an earlier version asked
        # whether a refusing exit appeared at all, and a mutation that turned
        # the unreadable-handshake path into a success passed it untouched,
        # because the other refusing exits still matched. Every ending that is
        # not the converged verdict must refuse (AGENTS.md 2).
        converged = wait_fn.count("HealthWait(true")
        if converged != 1:
            fail("the deferred retry's wait has %d converged exits; exactly one "
                 "is allowed and it must be the one guarded by permitsDispatch - "
                 "any other way out that reports success turns an unreadable or "
                 "unconverged handshake into permission to tear userspace down"
                 % converged)
        if not re.search(r"if \(SoftRebootHealthPolicy\.permitsDispatch\(verdict\)\)"
                         r" \{\s+return HealthWait\(true", wait_fn):
            fail("the deferred retry's one converged exit is not the handshake's "
                 "own verdict; a wait that succeeds on anything else is a sleep "
                 "pretending to be a condition")
        # ...and every other ending is its OWN durable reason, never one
        # collapsed value. A Boolean here put an exhausted budget, a
        # CRASH_RECOVERY verdict, an unreadable handshake, a lost clock and an
        # interrupted sleep on one trace line; those have different next steps
        # and the trace is the only record that survives a boot that does not
        # come back (3.7, Codex on PR #85).
        for reason in ("RETRY_HEALTH_TIMEOUT", "RETRY_HEALTH_UNREADABLE",
                       "RETRY_HEALTH_NO_CLOCK", "RETRY_HEALTH_INTERRUPTED"):
            if reason not in wait_fn:
                fail("the deferred retry's wait no longer reaches %s; collapsing "
                     "it into another ending makes two different investigations "
                     "read as one line (3.7)" % reason)
        if wait_fn.count("HealthWait(false") < 4:
            fail("the deferred retry's wait has fewer than four refusing exits; "
                 "an exhausted budget, an unreadable handshake, a lost clock and "
                 "an interrupted wait are four endings, and absence of a reading "
                 "is never a pass (2)")
        # The timeout carries the verdict it was stuck at, or "exhausted at
        # PENDING" and "exhausted at CRASH_RECOVERY" are indistinguishable.
        if not re.search(r"HealthWait\(false, RETRY_HEALTH_TIMEOUT, last",
                         wait_fn):
            fail("the deferred retry's timeout no longer records the last "
                 "handshake verdict it observed; a rollback already in flight "
                 "and a merely slow boot then read identically")
        # And the reason reaches the TRACE, not only logcat: logcat does not
        # survive the reboot this operation can cause.
        if ".detail()" not in retry_fn:
            fail("the deferred retry writes a trace detail that does not carry "
                 "the wait's terminal reason; logcat may not survive what this "
                 "operation can do to the boot (3.6.1)")
        if "RETRY_HEALTH_BUDGET_MS} ms" in retry_fn:
            fail("the deferred retry logs the whole budget as the time waited; "
                 "every non-convergent exit but the timeout returns early, so "
                 "that line states a duration that did not happen")

        # (R5) It decides off system_server's looper. This receiver is hosted in
        #      the system process; three record reads and an fsync'd append
        #      inline would delay every boot of every install, permanently.
        if "Thread(task" not in retry_fn:
            fail("the deferred retry runs on the receiver's looper; that looper "
                 "is system_server's main thread, and the decision reads three "
                 "durable records and fsyncs a trace line")

    # (R6) The policy's second-teardown guard stays. A soft reboot restarts
    #      userspace, not the kernel, so boot_id survives it and BOOT_COMPLETED
    #      arrives again with the chain's DISPATCH line still in the trace. The
    #      per-boot lock is the only thing that separates "the receiver refused
    #      before claiming" from "the teardown already ran", and that
    #      distinction is the whole basis of this retry.
    retry_policy = policy_src[policy_src.find("public static String chainSoftRebootRetry("):]
    retry_policy = retry_policy[:retry_policy.find("\n    public static boolean traceHasStepDetail")] \
        or retry_policy
    if "SoftRebootPolicy.parseLock(" not in retry_policy:
        fail("chainSoftRebootRetry no longer reads the per-boot soft-reboot lock "
             "through SoftRebootPolicy.parseLock; without it a SUCCESSFUL soft "
             "reboot - which keeps the same boot_id - is followed by a second "
             "teardown, and a second parser for those bytes would be a second "
             "answer to whether this boot's attempt was spent (3.5)")
    for required in ("CHAIN_SOFT_REBOOT_RETRY_ALREADY_CLAIMED",
                     "CHAIN_SOFT_REBOOT_RETRY_ALREADY_RETRIED",
                     "CHAIN_SOFT_REBOOT_RETRY_LOCK_UNREADABLE",
                     "CHAIN_SOFT_REBOOT_RETRY_TRACE_UNREADABLE"):
        if required not in retry_policy:
            fail("chainSoftRebootRetry no longer reaches %s; every one of these "
                 "is a boot loop or an unasked-for teardown if it is dropped, "
                 "and an unreadable record is never a pass (2)" % required)
    # ...and it re-reads the authorisation rather than trusting its own trace.
    # The trace line says the chain asked; it does not say the arming still
    # stands. chainSoftReboot can only REMOVE permission here.
    if "chainSoftReboot(armRecord, cycleRecord, currentBootId, true)" not in retry_policy:
        fail("chainSoftRebootRetry no longer re-derives the arm/cycle "
             "authorisation through chainSoftReboot; a trace line from earlier "
             "in the boot is a record that something was asked, never a standing "
             "permission (3.11)")

    # The floor must stay below the structural AMS floor, or the clock is back
    # to choosing the moment. Asserted here and not in EarlyRootPolicyTest
    # because it is a Kotlin constant and a Java host test cannot read it.
    early_root_latency = re.search(
        r"const val MINIMUM_LATENCY_MS = ([0-9_]+)L",
        code_only(dfr_source("DfrEarlyRoot.kt")))
    if not early_root_latency:
        fail("DfrEarlyRoot.MINIMUM_LATENCY_MS is unreadable; the dispatch floor "
             "is what keeps the readiness wait able to find the hop")
    else:
        floor = int(early_root_latency.group(1).replace("_", ""))
        if floor >= 13312:
            fail("the dispatch floor is %d ms, at or past "
                 "boot_progress_ams_ready (13312 ms in cea5208c); AMS starts no "
                 "app process before that, so the clock and not the wait is "
                 "again choosing the moment" % floor)
    # And the probe's own floor is NOT dragged along with it. It is a measuring
    # instrument with four boots of samples taken against a 15 s floor;
    # re-basing it silently invalidates every comparison those samples exist
    # for, and the probe does not race the animation anyway (AGENTS.md 3.11:
    # each trigger's policy is its own).
    probe_latency = re.search(
        r"const val MINIMUM_LATENCY_MS = ([0-9_]+)L",
        code_only(dfr_source("DfrEarlyBootProbe.kt")))
    if not probe_latency:
        fail("DfrEarlyBootProbe.MINIMUM_LATENCY_MS is unreadable")
    elif int(probe_latency.group(1).replace("_", "")) != 15000:
        fail("the probe's floor moved off 15 s; it is an instrument with four "
             "boots of samples taken against that floor, and re-basing it "
             "makes the next comparison measure something else")
    # The probe must not acquire the wait either: a sweep loop on its looper
    # would move the quantity it measures, which is the defect 3.11 names.
    if "readinessWait" in code_only(dfr_source("DfrEarlyBootJobService.kt")):
        fail("the observation-only probe service references the readiness "
             "wait; a wait on that looper moves the quantity it measures")

    # --- the native profile ---------------------------------------------
    # The measurement of the 5767 ms that boot 2e7d56e5 could not account for.
    # Four properties, and each one is the difference between a measurement and
    # a thing that changes or misreports what it measures.
    coord_src = code_only(dfr_source("DfrRootCoordinator.kt"))
    # (1) ONE emit, and it is AFTER the post-root wait, not inside the
    #     transaction. DirtyFrag.report() uses IBinder.FLAG_ONEWAY, so the
    #     remote does not wait for our onTransact and callbacks can still be in
    #     flight when transaction 5 returns - reading the accumulator there
    #     yields a partial timeline that LOOKS complete. A wait taken there
    #     would also sit on the critical path, lengthening the measured
    #     interval. Codex caught both on PR #69.
    if coord_src.count("host.nativeProfile(") != 1:
        fail("DfrRootCoordinator does not emit the native profile exactly once; "
             "one line, after the fact, is the whole contract")
    emit_at = coord_src.find("host.nativeProfile(")
    wait_at = coord_src.find("awaitPostRootComplete(")
    tx_at = coord_src.find("c.transact(5,")
    if emit_at < 0:
        fail("DfrRootCoordinator no longer emits the native profile; the "
             "transaction's internal timeline exists nowhere else - its "
             "reporter strings go to a UI log an early boot does not have")
    elif tx_at < 0 or emit_at < tx_at:
        fail("DfrRootCoordinator emits the native profile before transaction 5; "
             "instrumentation that lengthens the interval it measures is "
             "worthless")
    elif wait_at < 0 or emit_at < wait_at:
        fail("DfrRootCoordinator emits the native profile before the post-root "
             "wait; the reporter is FLAG_ONEWAY, so callbacks can still be "
             "arriving and the timeline would be partial without saying so")
    # (2) the settle is BOUNDED and it reports itself. An unbounded wait on a
    #     one-way stream never returns; a silent one makes "quiet" and "gave up
    #     waiting for quiet" the same line (3.7).
    for token in ("NATIVE_PROFILE_SETTLE_MAX_MS", "NATIVE_PROFILE_QUIET_MS",
                  "settle_ms=", "SETTLE_TIMEOUT"):
        if token not in coord_src:
            fail("the native profile's settle is missing %s; an unbounded wait "
                 "on a one-way stream never returns, and a silent one cannot "
                 "say whether it reached quiet or gave up" % token)
    # (3) the accumulator is written from BINDER THREADS while this thread is
    #     blocked inside transact(5), then read after. transact returning
    #     establishes no happens-before with those writes, and nothing says the
    #     pool uses one thread for all of them.
    if "ConcurrentLinkedQueue" not in coord_src or "AtomicInteger" not in coord_src:
        fail("the native profile accumulator is not concurrent; the reporter's "
             "callbacks run on binder threads while transact(5) blocks this "
             "one, so a plain list races on both visibility and structure")
    # (4) the retention keeps the TAIL. A leading cap spends itself inside the
    #     three gate_target calls - 51 REPORT sites each, all before runAll's
    #     trigger loop - so every successful run would come back truncated
    #     without the one part the measurement exists for. The rule itself is in
    #     Java and host-tested; this only pins that the Kotlin uses it.
    if "EarlyRootPolicy.profileWindow(" not in coord_src:
        fail("DfrRootCoordinator no longer applies the host-tested retention "
             "window; a leading cap loses the trigger loop, which is the only "
             "part of the timeline anyone is waiting to see")
    if "NATIVE_PROFILE_TAIL_MARKS" not in coord_src:
        fail("the native profile keeps no explicit tail; the trigger loop "
             "reports last, so a head-only window drops the measurement")
    # (5) no gate reads it. It is evidence about timing, never permission.
    if "profileWindow" not in code_only(dfr_source("EarlyRootPolicy.java")):
        fail("EarlyRootPolicy.profileWindow is gone; the retention rule has to "
             "stay where the host suite can prove it, because a leading cap "
             "passed every static check and would have wasted the physical run")
    if "nativeProfile" in probe_policy_src_for_gate_check:
        fail("EarlyBootProbePolicy reads the native profile; it is a timing "
             "measurement and must never reach a gate")
    if "STEP_NATIVE_PROFILE" not in code_only(dfr_source("EarlyRootPolicy.java")):
        fail("EARLY_ROOT_NATIVE_PROFILE is not declared; parseTraceLine drops "
             "any step outside the closed set, so the profile would be written "
             "and then unreadable")

    # The reason is passed BY NAME, and that is a correctness requirement, not
    # style. `stopReason` sits before the trailing `abandoned` lambda in
    # gateAndDispatch's parameter list, so a caller that passed its lambda
    # positionally would bind it to the wrong parameter. Trailing-lambda syntax
    # (DfrBootReceiver's `) { false }`) binds to the LAST parameter and takes
    # the default, which is correct; the job service's extra argument has to be
    # named for the same reason.
    if "stopReason = {" not in early_root_job_src:
        fail("DfrEarlyRootJobService no longer passes stopReason by name; it "
             "sits before the trailing abandoned lambda, so a positional "
             "argument binds to the wrong parameter")

    # And the boundary writers must not take a live reading of their own. This
    # is the P2 Codex caught on PR #68: the first version read the thermal
    # status inside abandon()/abandonIfStopped(), which can be seconds after
    # the stop.
    for name, src in (("DfrEarlyRootDispatch", early_root_dispatch_src),
                      ("DfrEarlyBootJobService", code_only(early_job_src))):
        boundary = src[src.find("private fun abandon"):] if "private fun abandon" in src else ""
        if "EarlyRootEnv.thermalStatus(" in boundary:
            fail("%s reads the thermal status at the abandonment boundary; it "
                 "must be captured in onStopJob and only carried here, or the "
                 "record pairs two different instants" % name)
    if "stopThermal = {" not in early_root_job_src:
        fail("DfrEarlyRootJobService no longer hands the captured thermal "
             "status to the dispatch by name; positionally it would bind to "
             "the wrong parameter")

    # Both records carry both diagnostics - checked on the RECORD, not on the
    # file. An earlier version of this guard searched the whole source, and a
    # mutation that stripped the trace detail still passed because the same
    # tokens survived in a neighbouring log line. A log line is gone before
    # anyone reads it on this firmware; the persisted record is the evidence.
    abandon_at = early_root_dispatch_src.find("private fun abandon(")
    if abandon_at < 0:
        fail("DfrEarlyRootDispatch no longer has an abandon() writer; a "
             "reclaimed execution would leave no record of why")
    else:
        # From the trace step to the end of that call: the record's own text.
        body = early_root_dispatch_src[abandon_at:]
        step_at = body.find("EarlyRootPolicy.STEP_REFUSED")
        record = body[step_at:body.find("\n    }", step_at)] if step_at >= 0 else ""
        for key in ("stop_reason=", "thermal_status="):
            if key not in record:
                fail("the early-root abandonment RECORD does not carry %s; the "
                     "boundary alone does not say why the scheduler stopped us, "
                     "and a log line does not survive to be read" % key)
    # code_only, so a comment mentioning the key cannot satisfy the guard, and
    # sliced to the end of the writer call rather than to the first ")" - the
    # record's own lines contain calls, so the first bracket closes one of them.
    early_job_code = code_only(early_job_src)
    stop_rec_at = early_job_code.find("EarlyBootProbePolicy.CALLBACK_STOPPED}")
    if stop_rec_at < 0:
        fail("the probe no longer writes a CALLBACK_STOPPED record")
    else:
        end = early_job_code.find("\n        )", stop_rec_at)
        stop_rec = early_job_code[stop_rec_at:end if end > 0 else len(early_job_code)]
        for key in ("stop_reason=", "thermal_status="):
            if key not in stop_rec:
                fail("the probe's stop RECORD does not carry %s, so the two "
                     "jobs' stops stop being comparable" % key)
    # Neither policy may take a LIVE thermal reading. They receive numbers as
    # parameters and EarlyRootEnv does the reading, which is what keeps the
    # decision host-testable and keeps a binder call out of a pure class.
    for name, src in (("EarlyRootPolicy", code_only(dfr_source("EarlyRootPolicy.java"))),
                      ("EarlyBootProbePolicy", probe_policy_src_for_gate_check)):
        for token in ("PowerManager", "currentThermalStatus",
                      "getCurrentThermalStatus", "getThermalHeadroom"):
            if token in src:
                fail("%s takes a live thermal reading (%s); the policies receive "
                     "numbers and EarlyRootEnv does the reading" % (name, token))
    # And the path that authorises THE CHAIN must not consult thermal at all.
    #
    # This replaces a blunter guard that forbade EarlyRootPolicy from naming any
    # thermal value. That premise expired when the owner asked for an
    # arming-time gate: there is now one legitimate thermal decision, and it
    # decides whether to ARM. The property worth keeping is narrower and
    # stronger - a dispatched callback proves the restriction was not in force,
    # so thermal inside the chain gate could only withhold a run the platform
    # already permitted.
    policy_full = code_only(dfr_source("EarlyRootPolicy.java"))
    for fn in ("public static Decision evaluate(",
               "public static Decision evaluateBeforeReadiness(",
               "public static Decision evaluateArmBinding("):
        at = policy_full.find(fn)
        if at < 0:
            fail("EarlyRootPolicy no longer declares %s; the chain's gate has "
                 "moved and this guard cannot speak for it" % fn.split("(")[0])
            continue
        end = policy_full.find("\n    }", at)
        if "hermal" in policy_full[at:end if end > 0 else len(policy_full)]:
            fail("%s consults a thermal value; the gate that authorises the "
                 "chain must not, because a dispatched callback already proves "
                 "the restriction was not in force" % fn.split("(")[0])

    # The probe's stop record gained keys, and its parser demands the key set
    # EXACTLY. Required keys would make every record an older build wrote parse
    # as malformed - good evidence refused because the reader got newer, which
    # is 3.6.1's rule in its original form: required to ACT, never to PARSE.
    probe_policy_src = code_only(dfr_source("EarlyBootProbePolicy.java"))
    if "CALLBACK_STOPPED_OPTIONAL_KEYS" not in probe_policy_src:
        fail("EarlyBootProbePolicy no longer separates the optional stop "
             "diagnostics; a required stop_reason refuses every record written "
             "before the field existed")
    for key in ("stop_reason", "thermal_status"):
        if key not in probe_policy_src:
            fail("EarlyBootProbePolicy does not name %r, so the writer and the "
                 "parser have drifted" % key)
        if '"%s"' % key in probe_policy_src.split(
                "CALLBACK_STOPPED_KEYS = Set.of(")[-1].split(")")[0]:
            fail("EarlyBootProbePolicy made %r a REQUIRED stop-record key; that "
                 "refuses every record written before the field existed" % key)

    for name, src in (("DfrEarlyRootJobService", early_root_job_src),
                      ("DfrBootReceiver", receiver_code)):
        if "DfrEarlyRootDispatch.gateAndDispatch(" not in src:
            fail("%s does not route through the shared early-root dispatch; a "
                 "second copy of the sequence is a second place to forget a gate"
                 % name)
    # Each trigger names itself, and the two names are different. One shared
    # entry step would hide which trigger got there - which is the measurement
    # this whole change exists to collect.
    if "EarlyRootPolicy.TRIGGER_JOB" not in early_root_job_src \
            or "EarlyRootPolicy.STEP_JOB_ENTERED" not in early_root_job_src:
        fail("the early-root job callback does not identify itself as the job "
             "trigger, so the trace cannot say which trigger reached the chain")
    if "EarlyRootPolicy.TRIGGER_LOCKED_BOOT" not in receiver_code \
            or "EarlyRootPolicy.STEP_TRIGGER_ENTERED" not in receiver_code:
        fail("DfrBootReceiver does not identify itself as the LOCKED_BOOT_COMPLETED "
             "trigger, so the trace cannot say which trigger reached the chain")
    # ...and the deterministic trigger runs off system_server's main looper,
    # before the Auto Root dispatch it shares the broadcast with. Inline, the AMS
    # reflection sweep and the fsync'd appends would delay the boot this trigger
    # exists to get ahead of.
    dispatch_call = receiver_code.find("dispatchEarlyRoot(context, arrivalMs)")
    optin_call = receiver_code.find("AutoRootStore.optInVerdict()")
    if dispatch_call < 0:
        fail("DfrBootReceiver no longer dispatches the deterministic early-root "
             "trigger; the persisted job is a floor, not a deadline, and on "
             "2026-10-13 the scheduler called it back 401 s past the window")
    elif not (dispatch_call < optin_call):
        fail("DfrBootReceiver dispatches Auto Root's opt-in read before the "
             "early-root trigger; that read is filesystem time taken out of the "
             "only budget the early path has")
    trigger_fn = receiver_code.find("private fun dispatchEarlyRoot(")
    if trigger_fn < 0 or 'Thread(task, "dfr-early-root-trigger")' not in \
            receiver_code[trigger_fn:]:
        fail("the deterministic early-root trigger does not run on a thread of its "
             'own; the receiver is hosted in process "system" and the dispatch '
             "would run on system_server's main looper")
    if re.search(r"dispatchEarlyRoot\([^)]*\)\s*\n\s*(EarlyRootStore|StageHop)",
                 receiver_code):
        fail("DfrBootReceiver does early-root I/O on the broadcast looper")

    # Same main-looper discipline as the probe, and for a stronger reason: this
    # callback is trying to get AHEAD of the boot's own broadcasts.
    root_start = early_root_job_src.find("override fun onStartJob")
    root_start_body = early_root_job_src[
        root_start:early_root_job_src.find("override fun onStopJob")]
    for banned in ("StageHop.", "EarlyRootStore.", "readBootId()",
                   "EarlyRootPolicy.evaluate", "DfrEarlyRootDispatch."):
        if banned in root_start_body.split("val task = Runnable {")[0]:
            fail("early-root onStartJob does blocking work (%r) before handing off "
                 "to the worker; it would delay the very broadcasts it is trying to "
                 "run ahead of" % banned)
    if "val callbackElapsedMs = EarlyRootEnv.monotonicNow()" not in root_start_body:
        fail("the early-root callback no longer reads its clock as the first "
             "statement; the early window is defined relative to that reading")
    if early_root_job_src.count("jobFinished(params, false)") != 1 \
            or "completionHandler.post" not in early_root_job_src \
            or "override fun onStopJob" not in early_root_job_src:
        fail("early-root job completion is not serialized with onStopJob on the "
             "main looper, or the one-shot no-reschedule contract was lost")
    if "JobInfo" in early_root_job_src:
        fail("the early-root callback builds a JobInfo; a self-rescheduling root "
             "attempt is exactly the shape that must not exist")
    if "token.stopped.get()" not in early_root_job_src:
        fail("the early-root callback no longer answers the dispatch's cancellation "
             "question, so a run the scheduler took back would walk into a dispatch")

    service_order = order(early_root_service_src,
                          "EarlyRootPolicy.STEP_SERVICE_ENTERED",
                          "StageHop.probeReadiness(",
                          "EarlyRootPolicy.evaluate(",
                          "EarlyRootPolicy.STEP_PREFLIGHT_PASS",
                          "EarlyRootStore.journalPhase(",
                          "DfrRootCoordinator.run(")
    if service_order is None or service_order != sorted(service_order):
        fail("the early-root service no longer re-derives the gate before claiming "
             "the boot's single attempt and running the chain; an intent that "
             "reaches it is a request, never an authorisation")
    if "AutoRootPolicy.PHASE_STARTED" not in early_root_service_src \
            or "EarlyRootPolicy.STEP_BEFORE_NATIVE" not in early_root_service_src:
        fail("the early-root service takes no pre-record before transaction 5")

    # --- the hop is a privileged step too -----------------------------------
    # Phase.WAIT_CONTROLLER is reported only after hopToNetworkStack RETURNED,
    # so a caller taking its record from a phase callback has none for the hop
    # itself: a process that died inside it leaves a trace ending at staging,
    # which reads exactly like a hop that was never attempted. The hop runs our
    # code in network_stack, where it dlopens libexp.so and arms stage 2, so
    # 3.6.1 covers it - record first, and a record that cannot be written
    # refuses the step.
    hop_order = order(coord_src, "if (!host.beforeHop())",
                      "StageHop.hopToNetworkStack(context)",
                      "host.phase(Phase.WAIT_CONTROLLER)")
    if hop_order is None or hop_order != sorted(hop_order):
        fail("DfrRootCoordinator no longer offers an abortable pre-hop boundary "
             "before StageHop.hopToNetworkStack; a caller's durable record of the "
             "hop would be a post-record, and a death inside the hop would be "
             "indistinguishable from a hop never attempted")
    # --- transaction 6 is a boundary of its own, in the durable record ------
    # The remote non-destructive preflight sits between CONTROLLER_READY and the
    # caller's point-of-no-return record, and it can refuse there. Collapsing it
    # into CONTROLLER_READY would make a trace ending at that step mean either
    # "the remote domain refused, nothing was written, Auto Root's own trigger
    # may still run later in this boot" or "the process did not survive to
    # beforeNativeRun" - two readings that send the next physical run to
    # different places, which is exactly what 3.7 forbids.
    preflight_order = order(coord_src,
                            "host.phase(Phase.CONTROLLER_READY)",
                            "c.transact(6, preflightData, preflightReply, 0)",
                            "host.phase(Phase.REMOTE_PREFLIGHT_PASS)",
                            "if (!host.beforeNativeRun())")
    if preflight_order is None or preflight_order != sorted(preflight_order):
        fail("DfrRootCoordinator no longer reports the remote preflight's success "
             "as its own phase between CONTROLLER_READY and beforeNativeRun; a "
             "caller's durable record could not tell a transaction-6 refusal "
             "from a death before the point of no return")
    if "EarlyRootPolicy.STEP_REMOTE_PREFLIGHT_PASS" not in early_root_service_src:
        fail("the early-root service does not record the remote preflight boundary, "
             "so its trace collapses a clean remote refusal into the same reading "
             "as a process that died before transaction 5")
    if "STEP_REMOTE_PREFLIGHT_PASS" not in early_root_policy_src:
        fail("EARLY_ROOT_REMOTE_PREFLIGHT_PASS left the closed step vocabulary; "
             "writing it would refuse and the boundary would go unrecorded")
    # --- the arming is one operation, and it has to say which one -----------
    # schedule() and the durable arm record cannot be made atomic, and the
    # window between them is reachable: a process that dies after the new job is
    # persisted and before the new record replaces the old leaves a NEW job
    # beside an OLD authorisation whose job id, namespace, version, ksud digest
    # and fingerprint all still agree. The policy's negative cases cover the
    # comparison; what cannot be unit-tested is that the token is actually
    # minted, stored in the JobInfo, verified to have survived the scheduler,
    # read back from the live callback and relayed to the service.
    for required, why in (
            ("SecureRandom()", "a counter resets with the process and a wallclock "
                               "can repeat across a reboot; either collision reads "
                               "as agreement"),
            ("EarlyRootPolicy.EXTRA_GENERATION", "the token is not put in the "
                                                 "JobInfo extras, so the callback "
                                                 "has nothing to be compared with"),
            ("pending.extras", "nobody checks that the scheduler actually stored "
                               "the extras; a dropped bundle would refuse every "
                               "callback in the boot the owner spent a reboot on")):
        if required not in early_root_arm_src:
            fail("the early-root arming no longer binds a generation token (%s): %s"
                 % (required, why))
    if "params.extras" not in early_root_job_src:
        fail("the early-root callback does not read the arming generation out of the "
             "live JobParameters; comparing our own file against itself proves the "
             "record self-consistent, not that it scheduled this job")
    if "in0.callbackGeneration" not in early_root_dispatch_src:
        fail("the early-root input builder does not supply the arming generation, "
             "so every gate that reads it compares nothing (3.2)")
    # The two triggers do NOT have the same evidence here, and the difference is
    # asserted rather than left to a comment: only the job callback may present a
    # token it did not read out of the arm record it is compared against.
    if "EarlyRootPolicy.TRIGGER_JOB == trigger" not in early_root_dispatch_src \
            or "EarlyRootPolicy.parseArm(armRecord)?.generation" not in \
            early_root_dispatch_src:
        fail("the early-root dispatch no longer distinguishes the scheduler's "
             "generation from the one read back out of the arm record; the "
             "broadcast trigger has no scheduler half, and pretending otherwise "
             "makes a self-comparison look like binding")
    if "generation" not in code_only(early_root_policy_src):
        fail("the arm record no longer carries a generation; an interrupted re-arm "
             "would leave a new job authorised by an old record")

    # --- the unresolved-incident latch is enforced at BOTH entry points -----
    # A journal left at STARTED with native_started=1 and no completion, in a
    # boot that is not this one, is a run that died after transaction 5. The
    # policy's own negative cases cover the decision
    # (EarlyRootPolicyTest); what cannot be unit-tested is the Kotlin that has
    # to supply the record, write it, and refuse without it.
    acknowledged = re.search(
        r"ACKNOWLEDGED_INCIDENT_BOOTS\s*=\s*Set\.of\(([^;]*)\);",
        early_root_policy_src, flags=re.S)
    acknowledged_boot = "5a7c2537-9693-44f9-8b2e-e26a1b3a10f2"
    if (not acknowledged or
            re.findall(r'"([^"]+)"', acknowledged.group(1)) != [acknowledged_boot] or
            re.sub(r'"[^"]+"|[\s,]', "", acknowledged.group(1))):
        fail("the acknowledged-incident list must contain only the examined "
             "2026-10-12 DZIF boot id as a fixed in-source exact match; a wildcard, "
             "parsed file or runtime clear would bypass the incident latch")
    if "in0.incidentRecord = EarlyRootStore.readIncident()" not in \
            early_root_dispatch_src:
        fail("the early-root input builder does not supply the incident record, so "
             "the latch evaluates it as absent and a previous boot's unexplained "
             "death stops refusing at every entry point (3.2)")
    for required, why in (
            ("EarlyRootPolicy.detectIncident(",
             "the arming no longer looks for an unaccounted-for previous boot - "
             "and it is the only place that can, because archivePreviousCycle() "
             "is about to move the journal aside and the arm record the "
             "attribution comes from is about to be overwritten"),
            ("EarlyRootStore.appendIncident(",
             "the arming no longer persists the incident it detected, so the "
             "evidence dies with the cycle that produced it"),
            ("EarlyRootPolicy.INCIDENT_IN_JOURNAL",
             "the arming no longer reports a detected incident as its own "
             "refusal, so the owner cannot tell it apart from an ordinary "
             "not-armed answer (3.7)")):
        if required not in early_root_arm_src:
            fail("early-root arming: %s (missing %s)" % (why, required))
    # The first arming after a historical incident must record it before
    # applying the exact historical-boot acknowledgement. An unconditional
    # INCIDENT_IN_JOURNAL return here makes that boot impossible to arm once;
    # every other newly detected incident still refuses on this first call.
    pending_at = early_root_arm_src.find("val pending = EarlyRootPolicy.detectIncident(")
    append_at = early_root_arm_src.find("val failure = EarlyRootStore.appendIncident(pending)")
    pending_guard_at = early_root_arm_src.find(
        "if (!EarlyRootPolicy.incidentAcknowledged(pending)) {")
    pending_refusal_at = early_root_arm_src.find(
        "return \"[x] EARLY_ROOT_NOT_ARMED: ${EarlyRootPolicy.INCIDENT_IN_JOURNAL}\"")
    if (min(pending_at, append_at, pending_guard_at, pending_refusal_at) < 0
            or not (pending_at < append_at < pending_guard_at < pending_refusal_at)):
        fail("the arming must persist a newly detected incident before using "
             "incidentAcknowledged() to exempt only the examined historical boot; "
             "an unconditional INCIDENT_IN_JOURNAL return ignores the owner's "
             "acknowledgement and prevents the first authorized arming")

    # Order: detect and record BEFORE the archive moves the journal. Reversed,
    # the detector reads a journal that is no longer there and the incident is
    # silently lost - which is the exact self-correction P0-D forbids.
    latch_order = order(early_root_arm_src,
                        "recordPendingIncident(",
                        "EarlyRootStore.archivePreviousCycle()")
    if latch_order is None or latch_order != sorted(latch_order):
        fail("the early-root arming archives the previous cycle before looking "
             "for an unresolved incident in it; the journal that carries the "
             "evidence is gone by then")
    if "INCIDENT_PATH" not in early_root_store_src:
        fail("EarlyRootStore no longer has a durable incident record; a field in "
             "the per-cycle journal cannot do this job, because "
             "archivePreviousCycle() moves that journal aside on the next arming")
    # The journal is examined on EVERY arming, not only when the log is empty or
    # when a recorded incident blocks. The branch that returned as soon as a
    # recorded incident did not block the current digest is the one the recovery
    # flow takes, and on it a SECOND unexplained death was archived unrecorded
    # and the artefact ran again. Codex review on PR #55.
    detect_at = early_root_arm_src.find("EarlyRootPolicy.detectIncident(")
    block_at = early_root_arm_src.find("EarlyRootPolicy.blockingIncident(")
    if detect_at < 0 or block_at < 0 or detect_at > block_at:
        fail("the early-root arming decides what a recorded incident blocks "
             "before it looks at the journal in front of it. On the branch where "
             "the recorded incident does not block the artefact being armed - "
             "which is exactly the corrected-artefact recovery flow - the new "
             "incident is never recorded, archivePreviousCycle() moves its "
             "journal aside, and the artefact runs again with its own "
             "unexplained death erased")
    # An unreadable or malformed journal is a refusal in the ARMING, not only in
    # the gate. detectIncident() answers null for both, and null means "nothing
    # pending" downstream, so without its own refusal the arming archived a
    # journal it could not account for - one that may say STARTED with
    # native_started=1 - and the gate's own two verdicts became unreachable for
    # anything older than the current cycle. Reported on PR #55.
    #
    # Scoped to recordPendingIncident()'s own body throughout. A whole-file
    # ordering would compare this function's DEFINITION site against arm()'s
    # CALL site, which says nothing about call order; what the archive ordering
    # needs is already covered by the recordPendingIncident -> archive check
    # above.
    detect_fn = early_root_arm_src.find("private fun recordPendingIncident(")
    detect_body = ""
    if detect_fn < 0:
        fail("the early-root arming no longer has recordPendingIncident(), so "
             "nothing examines the previous cycle before it is archived")
    else:
        detect_body = early_root_arm_src[detect_fn:]
        next_fn = detect_body.find("\n    fun ", 1)
        if next_fn > 0:
            detect_body = detect_body[:next_fn]

        for required, why in (
                ("EarlyRootPolicy.JOURNAL_UNREADABLE",
                 "the arming does not refuse an unreadable previous journal, so "
                 "archivePreviousCycle() destroys the only evidence that a run "
                 "reached transaction 5"),
                ("EarlyRootPolicy.JOURNAL_MALFORMED",
                 "the arming does not refuse a previous journal this build "
                 "cannot account for, so a record written by a run that died "
                 "mid-write is archived unexamined")):
            if required not in detect_body:
                fail("early-root arming: %s (missing %s)" % (why, required))

        # Both refusals come before the detection they guard: detectIncident()
        # answers null for an unaccountable journal, and null means "nothing
        # pending" to everything after it.
        unaccountable_order = order(detect_body,
                                    "EarlyRootPolicy.JOURNAL_UNREADABLE",
                                    "EarlyRootPolicy.JOURNAL_MALFORMED",
                                    "EarlyRootPolicy.detectIncident(")
        if unaccountable_order is None \
                or unaccountable_order != sorted(unaccountable_order):
            fail("recordPendingIncident() runs detectIncident() before deciding "
                 "whether the journal could be read or parsed at all; it answers "
                 "null for both, so the refusals have to come first")

        # One read, into a local. Two reads of a mutable file are two answers,
        # and the second is the one that would decide. armState() legitimately
        # reads the journal again to render the UI row, hence the scoping.
        reads = detect_body.count("EarlyRootStore.readJournal()")
        if reads != 1:
            fail("recordPendingIncident() reads the journal %d times, not once; "
                 "the unreadable check, the malformed check and the detection "
                 "must all judge the same bytes" % reads)
    if "parseIncidents(" not in early_root_arm_src:
        fail("the early-root arming reads the incident log as a single record. "
             "One record means the first incident occupies the only slot and a "
             "second one, on a corrected artefact, is lost")
    if "MAX_INCIDENTS" not in code_only(early_root_policy_src) \
            or "incidentLogHasRoom" not in early_root_store_src:
        fail("the incident log has no bound, or the store does not check it; an "
             "append-only file in /data/system that grows without limit is a "
             "defect of its own (the rule MAX_TRACE_STEPS states)")
    archive_body = early_root_store_src[
        early_root_store_src.find("private fun archiveLocked("):]
    archive_body = archive_body[:archive_body.find("fun journalPhase(")]
    if "INCIDENT_PATH" in archive_body:
        fail("archivePreviousCycle() archives the incident record. An "
             "unexplained death has to outlive the cycle it happened in, or "
             "re-arming erases the only thing that remembers it")

    # --- inside the window is not the same as before boot completion --------
    # The window bounds the clock, not the boot: a persisted callback restored
    # at 43 s in a boot that completed at 30 s satisfies the 120 s bound. The
    # policy's own negative cases cover the gate (EarlyRootPolicyTest); what
    # cannot be unit-tested is that both entry points actually SUPPLY the
    # reading, and that it is re-taken at the point of no return - everything
    # between the gate and transaction 5 takes real time, and the property can
    # move inside it.
    for name, src in (("DfrEarlyRootDispatch", early_root_dispatch_src),):
        if "EarlyRootEnv.bootCompletedState()" not in src:
            fail("%s does not supply the boot-completion reading, so the gate "
                 "evaluates it as absent and the early path would refuse every "
                 "run - or, if the refusal is removed, run after boot completion "
                 "and be recorded as evidence for an ordering it violated" % name)
    # Scoped to the method body: the Inputs population reads the same accessor
    # earlier in the file, so a whole-file ordering would pass on that alone.
    recheck_at = early_root_service_src.find("override fun beforeNativeRun()")
    recheck_body = early_root_service_src[recheck_at:] if recheck_at >= 0 else ""
    recheck = order(recheck_body,
                    "EarlyRootEnv.bootCompletedState()",
                    "EarlyRootPolicy.BOOT_NOT_COMPLETED",
                    "EarlyRootStore.journalPhase(")
    if recheck_at < 0 or recheck is None or recheck != sorted(recheck):
        fail("the early-root service no longer re-reads the boot state at the "
             "point of no return; sys.boot_completed can go to 1 during the "
             "readiness sweep, staging, the hop and the 90 s controller wait, and "
             "a run that crosses that line mid-flight is not the early path")
    if "EarlyRootEnv.bootCompletedState()" in early_root_store_src:
        fail("EarlyRootStore reads the boot state; the decision belongs in the "
             "pure policy, and a second reader is a second place it can start "
             "answering a plausible default")
    before_hop = early_root_service_src.find("override fun beforeHop()")
    if before_hop < 0:
        fail("the early-root service does not implement beforeHop, so it takes no "
             "pre-record for the hop")
    else:
        hop_body = early_root_service_src[before_hop:]
        hop_body = hop_body[:hop_body.find("override fun beforeNativeRun()")]
        if "EarlyRootPolicy.STEP_STAGEHOP_SENDING" not in hop_body \
                or "return false" not in hop_body:
            fail("beforeHop does not record the pre-hop step, or does not refuse "
                 "when it cannot be persisted")
    # The regression this rename fixed: the coordinator reports STAGE_KSUD BEFORE
    # it calls stageFromAssets and before the KSUD_STAGED_VERIFY=PASS check, so a
    # step named STAGED claimed the daemon was staged in exactly the runs where
    # staging threw or failed its digest - replacing the real failure boundary
    # with an invented one.
    if "EARLY_ROOT_KSUD_STAGED" in early_root_policy_src:
        fail("the ksud trace step claims STAGED again; the coordinator reports "
             "that phase before staging is attempted, so the name is false in "
             "every failing run")
    if "EarlyRootPolicy.STEP_KSUD_STAGING" not in early_root_service_src:
        fail("the early-root service no longer records that it reached staging")

    # --- the two triggers guard each other in BOTH directions ---------------
    # One direction only is 3.2 at the scale of the feature. The reachable hole:
    # Auto Root is triggered by LOCKED_BOOT_COMPLETED (17.6-19.7 s on this
    # device) and a persisted job can be restored any time inside the 120 s
    # window, so Auto Root can reach transaction 5 first; if its native side
    # failed before stage1 created /dev/df, the marker probe answers a clean
    # ENOENT and nothing else would refuse.
    # Substrings that survive the source's own line wrapping: a guard anchored
    # on a reflowed literal fails on correct code, and a guard that fails on
    # correct code gets weakened or deleted, which is how the property is really
    # lost.
    for required in ("autoRootJournalRecord",
                     "AUTO_JOURNAL_UNREADABLE, \"the Auto Root journal exists but\"",
                     "\"Auto Root already reached phase \""):
        if required not in early_root_policy_src:
            fail("EarlyRootPolicy no longer refuses on Auto Root's journal (%r "
                 "missing); a failed Auto Root attempt that wrote no marker would "
                 "let the early callback issue a second native transaction in the "
                 "same boot" % required)
    if "in0.autoRootJournalRecord = AutoRootStore.journal()" not in \
            early_root_dispatch_src:
        fail("the early-root input builder does not supply Auto Root's journal, so "
             "the policy's check is fed nothing and refuses nothing")
    before_native = early_root_service_src.find("override fun beforeNativeRun()")
    if before_native < 0:
        fail("the early-root service does not implement beforeNativeRun; the "
             "one-attempt-per-boot guarantee would rest on nothing")
    else:
        body = early_root_service_src[before_native:]
        body = body[:body.find("DfrRootCoordinator.run(")] if \
            body.find("DfrRootCoordinator.run(") > 0 else body
        native_order = order(body, "AutoRootPolicy.PHASE_STARTED",
                             "EarlyRootPolicy.STEP_BEFORE_NATIVE", "return true")
        if native_order is None or native_order != sorted(native_order):
            fail("beforeNativeRun returns true before both durable pre-records are "
                 "written; a crash after transaction 5 could then be followed by a "
                 "second attempt in this boot, or by a reboot nobody can attribute")
        if body.count("return false") < 2:
            fail("beforeNativeRun does not abort on a failed pre-record; the run "
                 "would proceed without the guarantee the record exists to give")
    # The second half of the integrated-boot goal USED to be forbidden here, and
    # this guard forbade it by name. The owner decided otherwise on 2026-10-15,
    # in the open: when post-root finishes, chain the soft reboot and accept
    # whatever moment that is, because landing inside the boot animation was
    # measured and is not reachable, and one visible blink beats unlocking,
    # waiting and tapping by hand.
    #
    # So the guard is EXCHANGED, not deleted - the same discipline AGENTS.md
    # 3.6.1 states for the reboot-syscall gate: whoever removes a guard replaces
    # it with one that proves the new boundary, and never with nothing. What the
    # old one bought was "no second path into the teardown"; that property is
    # now bought by the five checks above (the decision is the pure function,
    # the dispatch goes through the receiver that re-derives every gate, the
    # trace precedes it, no boot phase is read, and the authorisation is
    # per-arming). What stays banned is everything that would be a SECOND COPY
    # of the teardown rather than a handoff to the one that exists.
    #
    # DfrSoftRebootReceiver and ACTION_APPLY_MODULES are therefore permitted in
    # the service - that IS the handoff - and still banned in the dispatch,
    # which runs before any root exists and has nothing to hand over.
    for forbidden in ("RootTransport", "SoftRebootPolicy", "__NR_reboot"):
        if forbidden in early_root_service_src or forbidden in early_root_dispatch_src:
            fail("the early-root service or dispatch re-implements part of the "
                 "soft-reboot path (%r) instead of handing off to "
                 "DfrSoftRebootReceiver; a second copy of that sequence is a "
                 "second place a gate can be forgotten (3.2)" % forbidden)
    for forbidden in ("DfrSoftRebootReceiver", "APPLY_MODULES"):
        if forbidden in early_root_dispatch_src:
            fail("the early-root DISPATCH references %r; the dispatch runs "
                 "before transaction 5 and before any root exists, so a "
                 "teardown reachable from there could fire with nothing rooted "
                 "and no post-root record to gate it" % forbidden)
    # ...and it does not OFFER it either. The soft reboot is a physical FAIL
    # twice with a cause nobody has measured; the early path has no evidence at
    # all. A notification action is one tap, mid-boot, and the owner has just
    # watched the device come up.
    if "offerApplyModules = false" not in early_root_service_src:
        fail("the early-root verdict may carry the Apply Modules action; a "
             "known-failing operation must not be offered from a path with no "
             "physical evidence, least of all while the boot animation is up")
    if "offerApplyModules: Boolean = true" not in code_only(notifier_src):
        fail("RootNotifier lost the Apply Modules opt-out, so the early path "
             "cannot suppress an action it must not offer")
    for forbidden in ("while (true)", "Thread.sleep("):
        if forbidden in early_root_service_src:
            fail("the early-root service polls or retries (%r); it has one attempt "
                 "per boot by construction and Auto Root's trigger owns the budget "
                 "for the rest of the boot" % forbidden)

    # Arming: one cycle at a time, bound to the component and to this build.
    for required in ("setPersisted(true)", "setMinimumLatency(MINIMUM_LATENCY_MS)",
                     "forNamespace(NAMESPACE)", "getPendingJob(JOB_ID)",
                     "existing.service != component", "AutoRootStore.isQualified()"):
        if required not in early_root_arm_src:
            fail("early-root arming lost identity/persistence guard %r" % required)
    arm_order = order(early_root_arm_src, "EarlyRootStore.archivePreviousCycle()",
                      "EarlyRootStore.writeArm(record)")
    if arm_order is None or arm_order != sorted(arm_order):
        fail("early-root arming writes the new arm record before archiving the "
             "previous cycle; the two must never be live together, or the row the "
             "owner reads before spending a reboot describes the wrong cycle")
    if "ARM_SAME_BOOT" not in early_root_policy_src:
        fail("the early-root policy no longer refuses a callback in its own arming "
             "boot; a framework restart keeps boot_id and is not a full reboot")
    # An upper bound beside the floor. Not the fix - the second trigger is - but
    # a persisted job with only a minimum latency is what produced a callback
    # 401 s past the window on 2026-10-13.
    if "setOverrideDeadline(OVERRIDE_DEADLINE_MS)" not in early_root_arm_src:
        fail("the early-root arming schedules a job with a floor and no deadline; "
             "setMinimumLatency is an EARLIEST bound and the scheduler is free to "
             "run the job whenever it likes afterwards")

    # --- one arming, one boot, one claimed run -----------------------------
    # Until the deterministic trigger existed, JobScheduler enforced this by
    # consuming the job. LOCKED_BOOT_COMPLETED arrives in EVERY boot, armed or
    # not, so without a durable record the same arm record would authorise a run
    # in every boot after the arming - the standing switch docs/EARLY_ROOT.md
    # section 6 says is an owner decision made in the open.
    for required, why in (
            ("CYCLE_PATH", "there is no durable cycle record, so nothing bounds an "
                           "arming to one boot or to one run"),
            ("fun bindCycle(", "nothing binds an arming to a boot"),
            ("fun claimCycle(", "nothing claims an arming exclusively, so both "
                                "triggers of one boot could dispatch")):
        if required not in early_root_store_src:
            fail("EarlyRootStore: %s (missing %s)" % (why, required))
    for fn in ("fun bindCycle(", "fun claimCycle("):
        body = early_root_store_src[early_root_store_src.find(fn):]
        body = body[:body.find("\n    fun ", 1) if body.find("\n    fun ", 1) > 0
                    else len(body)]
        if "synchronized(lock)" not in body:
            fail("EarlyRootStore.%s does not serialise its read-modify-write; the "
                 "two triggers race each other into it and both live in process "
                 '"system"' % fn)
    if 'listOf(JOURNAL_PATH, TRACE_PATH, CYCLE_PATH)' not in early_root_store_src:
        fail("archivePreviousCycle no longer moves the cycle record aside with the "
             "journal and the trace; a new arm record beside the previous cycle is "
             "the state in which 'has this fired?' has no answer")
    archive_list = re.search(r"listOf\(JOURNAL_PATH[^)]*\)", early_root_store_src)
    if archive_list and "INCIDENT_PATH" in archive_list.group(0):
        fail("archivePreviousCycle moves the incident log aside; an unexplained "
             "death has to outlive the cycle it happened in, which is the whole "
             "reason it is a separate record")
    for required in ("CYCLE_BOUND", "CYCLE_CLAIMED", "ARM_EXPIRED",
                     "ARM_ALREADY_CLAIMED", "CLAIM_MISSING", "CLAIM_NOT_THIS_BOOT",
                     "CYCLE_FOREIGN"):
        if required not in early_root_policy_src:
            fail("EarlyRootPolicy lost the cycle verdict %s; one arming would stop "
                 "meaning one run" % required)
    # The service's authorisation is a claim of its own, not merely a gate that
    # passes: anything sharing uid 1000 can call startService on a non-exported
    # component of its own package's process.
    if "EarlyRootPolicy.ROLE_CLAIMED_RUN" not in early_root_service_src:
        fail("the early-root service does not present itself as the claimed run, so "
             "it is not gated on a claim and anything in our shared uid could start "
             "it and be let through by the readiness-and-marker gate alone")
    if "EarlyRootPolicy.ROLE_DISPATCH" not in early_root_dispatch_src:
        fail("the early-root dispatch does not present itself as a trigger, so the "
             "cycle record would be read from the wrong side")
    trigger_fn = early_root_service_src.find("private fun trigger(")
    if trigger_fn < 0 or "parseCycle(cycleRecord)?.trigger" not in \
            early_root_service_src[trigger_fn:]:
        fail("the early-root service takes the claiming trigger from the intent "
             "rather than from the claim record; an intent extra can be set by "
             "anything sharing our uid")

    # --- the animation is an element, not a comment ------------------------
    # The fact the product requirement is actually stated in. On 2026-10-13 the
    # callback arrived with bootanim_exit=1 as well as sys.boot_completed=1, and
    # a run inside the window, before boot completion, after the animation left
    # the screen would still be a second visible initialisation.
    for required in ("BOOTANIM_RUNNING", "BOOTANIM_EXITED", "BOOTANIM_ALREADY_EXITED",
                     "BOOTANIM_STATE_UNKNOWN", "in.bootanimState"):
        if required not in early_root_policy_src:
            fail("EarlyRootPolicy no longer weighs the boot-animation state (%r "
                 "missing); 'early' would be back to meaning 'soon after the kernel "
                 "started'" % required)
    if "in0.bootanimState = EarlyRootEnv.bootanimState()" not in early_root_dispatch_src:
        fail("the early-root input builder does not supply the boot-animation "
             "reading, so the gate evaluates it as absent and refuses every run - "
             "or, if that refusal is removed, runs after the screen was handed to "
             "the launcher")
    anim_fn = early_root_env_src.find("fun bootanimState()")
    anim_body = early_root_env_src[anim_fn:] if anim_fn >= 0 else ""
    anim_body = anim_body[:anim_body.find("\n    fun ", 1)] if \
        anim_body.find("\n    fun ", 1) > 0 else anim_body
    if anim_fn < 0 or 'raw == "1"' not in anim_body \
            or "EarlyRootPolicy.BOOTANIM_RUNNING" not in anim_body \
            or "EarlyBootProbePolicy.UNKNOWN" not in anim_body:
        fail("EarlyRootEnv.bootanimState does not map an unset property to RUNNING "
             "and a throwing lookup to UNKNOWN; one of those mistakes refuses every "
             "genuine early run and the other reads an absence as permission")
    recheck = early_root_service_src.find("override fun beforeNativeRun()")
    recheck_body = early_root_service_src[recheck:] if recheck >= 0 else ""
    recheck_body = recheck_body[:recheck_body.find("DfrRootCoordinator.run(")] if \
        recheck_body.find("DfrRootCoordinator.run(") > 0 else recheck_body
    if "EarlyRootEnv.bootanimState()" not in recheck_body:
        fail("the point of no return does not re-read the boot-animation state; "
             "everything between the gate and transaction 5 takes real time and the "
             "two properties move at different moments on this firmware")

    # BOOT_COMPLETED_OBSERVED is written once per boot, and the FIRST line wins.
    # ACTION_BOOT_COMPLETED is re-delivered by a framework restart under the same
    # boot_id - that is the property the soft-reboot path relies on - and on the
    # first PASS boot it happened 66 minutes in, leaving the trace ending 66
    # minutes past the moment the milestone is measured against.
    observed_fn = receiver_code.find("private fun recordEarlyRootBootCompleted(")
    observed_body = receiver_code[observed_fn:] if observed_fn >= 0 else ""
    observed_body = observed_body[:observed_body.find("\n    private fun ", 1)] if \
        observed_body.find("\n    private fun ", 1) > 0 else observed_body
    if observed_fn < 0 or "EarlyRootPolicy.traceHasStep(" not in observed_body:
        fail("BOOT_COMPLETED_OBSERVED can be appended more than once in one boot; "
             "a re-delivered broadcast would move the number the milestone is "
             "measured against")
    guard_at = observed_body.find("EarlyRootPolicy.traceHasStep(")
    write_at = observed_body.find("EarlyRootStore.trace(")
    if not (0 < guard_at < write_at):
        fail("the BOOT_COMPLETED_OBSERVED idempotence check runs after the append "
             "it is supposed to prevent")
    if "traceHasStep" not in early_root_policy_src:
        fail("EarlyRootPolicy lost traceHasStep, so the writer's idempotence check "
             "rests on nothing")
    # The locked-boot timestamp survives that stand-down as a PASSIVE observation.
    # On the first PASS boot the dispatch trigger's incidental TRIGGER_ENTERED at
    # 21259 ms was the only line bracketing the animation's exit to within 2.5 s;
    # standing the trigger down for a spent arming would have taken the
    # measurement with it, and the margin is what the remaining work has to
    # measure. The owner's review on PR #64 caught that.
    locked_fn = receiver_code.find("private fun recordEarlyRootLockedBoot(")
    locked_body = receiver_code[locked_fn:] if locked_fn >= 0 else ""
    locked_body = locked_body[:locked_body.find("\n    private fun ", 1)] if \
        locked_body.find("\n    private fun ", 1) > 0 else locked_body
    if locked_fn < 0:
        fail("the locked-boot arrival is no longer observed anywhere; the only "
             "sample inside the window where bootanim_exit and sys.boot_completed "
             "move would be gone, and with it the visual margin")
    else:
        for required, why in (
                ("EarlyRootPolicy.STEP_LOCKED_BOOT_OBSERVED",
                 "it writes no step of its own"),
                ("EarlyRootPolicy.traceBelongsToBoot(",
                 "it would append to last boot's record (3.8), and every boot of "
                 "every install would pay for it"),
                ("EarlyRootPolicy.traceHasStep(",
                 "a framework restart re-delivers the broadcast under the same "
                 "boot_id, and the measurement is about the first arrival")):
            if required not in locked_body:
                fail("the passive locked-boot observation is unsound: %s (%r "
                     "missing)" % (why, required))
        # Passive means passive: it may not arm, claim, dispatch or gate.
        for forbidden in ("claimCycle", "bindCycle", "startService",
                          "gateAndDispatch", "evaluateArmBinding",
                          "journalPhase"):
            if forbidden in locked_body:
                fail("the locked-boot observation reaches a decision path (%r); a "
                     "component that may refuse is not one that can be trusted to "
                     "leave a timestamp behind" % forbidden)
    if "STEP_LOCKED_BOOT_OBSERVED" not in early_root_policy_src:
        fail("EARLY_ROOT_LOCKED_BOOT_OBSERVED left the closed step vocabulary; "
             "writing it would refuse and the sample would go unrecorded")
    if "EarlyRootPolicy.STEP_LOCKED_BOOT_OBSERVED" in early_root_dispatch_src:
        fail("the dispatch writes the passive locked-boot observation; the "
             "observer must be the component that is not part of what it measures")

    # And the trigger that fires in EVERY boot stands down silently once the
    # arming it would serve is claimed: an arm record outlives its cycle, so
    # without this the evidence file of the boot being measured collects two
    # fsync'd appends per broadcast for a refusal the cycle record already proves.
    spent_at = early_root_dispatch_src.find("val spent = EarlyRootPolicy.parseCycle(")
    crumb_at = early_root_dispatch_src.find("val breadcrumb = EarlyRootStore.trace(")
    if spent_at < 0 or not (spent_at < crumb_at):
        fail("the early-root dispatch writes its breadcrumb before noticing that "
             "this arming is already claimed; the broadcast trigger fires in every "
             "boot and would keep appending to a spent cycle's trace")
    if "EarlyRootPolicy.TRIGGER_JOB != trigger" not in \
            early_root_dispatch_src[spent_at - 400:spent_at + 200]:
        fail("the spent-arming stand-down is not scoped to the trigger that fires "
             "every boot; the job's breadcrumb in that state is the punctuality "
             "measurement this path collects")

    # The row the owner reads before spending a reboot must read the cycle, not
    # only the arm record. Reading only the arm record is how it reported ARMED
    # over an arming that had already been claimed and run.
    arm_state = early_root_arm_src.find("fun armState(")
    arm_state_body = early_root_arm_src[arm_state:] if arm_state >= 0 else ""
    for required in ("EarlyRootStore.readCycle()", "cycle.claimed()",
                     "jobState(context)"):
        if required not in arm_state_body:
            fail("the early-root row no longer derives its answer from the cycle "
                 "record and the scheduler (%r missing); the arm record outlives "
                 "its cycle, so on its own it answers nothing" % required)

    # The trace store: serialised, boot-scoped, and honest about a failed clock.
    if "synchronized(lock)" not in early_root_store_src:
        fail("EarlyRootStore no longer serialises its read-modify-write sequences; "
             'the callback worker and the service thread share process "system"')
    if 'if (elapsedMs < 0) return "monotonic_clock_unavailable"' \
            not in early_root_store_src:
        fail("a failed monotonic reading can still be appended to the early-root "
             "trace; a successful write is not timing evidence")
    if "EarlyRootPolicy.traceBelongsToBoot(" not in early_root_store_src \
            or "$TRACE_PATH.prev" not in early_root_store_src:
        fail("the early-root trace is appended across boots instead of rotated; one "
             "apparent sequence spanning two boots is what AGENTS.md 3.8 forbids")
    if "EarlyRootPolicy.traceHasRoom(" not in early_root_store_src:
        fail("the early-root trace is unbounded; something re-entering would grow a "
             "file in /data/system without limit")

    # --- absence is ENOENT and nothing else ---------------------------------
    # File.exists() answers a boolean to a question with three answers: it is
    # false for ANY failed stat, EACCES and EIO included, and it does not throw.
    # A journal that is present and unreachable would therefore read as "this
    # boot has done nothing", while it may say STARTED - an absence turned into
    # permission to proceed (AGENTS.md 2), and the same defect markerState()
    # already carries the Os.stat fix for. This cannot be unit-tested here
    # (Android imports), so AGENTS.md 5's static rule applies.
    if ".exists()" in early_root_store_src:
        fail("EarlyRootStore is back to File.exists(); it cannot then tell an "
             "unreadable record from an absent one, which is what its own read() "
             "contract promises and what the journal cross-guard depends on")
    for required in ("Os.stat(path)", "OsConstants.ENOENT"):
        if required not in early_root_store_src:
            fail("EarlyRootStore no longer establishes absence through %s; only "
                 "ENOENT is absence, every other errno is missing evidence"
                 % required)
    if early_root_store_src.count("OsConstants.ENOENT") < 2:
        fail("only one of EarlyRootStore's two stat sites distinguishes ENOENT; "
             "the archive skipping an unreachable journal leaves the previous "
             "cycle's record beside a fresh arm record, which is the ambiguity "
             "the archive exists to remove")

    # One answer per boot to "has the chain already run here". The marker probe
    # cannot give it: once root is established on this firmware the /dev/df*
    # lookups answer EACCES rather than ENOENT and read as MARKER_UNKNOWN.
    # Anchored on the refusals themselves, not on the field name: a field can be
    # renamed and still be read, while a deleted check takes its reason strings
    # with it. The two below are the whole content of the rule - an unreadable
    # record refuses, and a boot the early path already reached refuses by name.
    for required in ("earlyRootJournalRecord",
                     "the Early Root journal exists but could not be read",
                     "Early Integrated Root already reached phase "):
        if required not in autoroot_policy_src:
            fail("AutoRootPolicy no longer refuses on the early-root journal (%r "
                 "missing); a boot in which the early path already ran the chain "
                 "would refuse only via MARKER_UNKNOWN, which cannot say why"
                 % required)
    if "q.earlyRootJournalRecord = EarlyRootStore.readJournal()" \
            not in code_only(autoroot_service_src):
        fail("the Auto Root service does not supply the early-root journal, so the "
             "policy's check is fed nothing and refuses nothing")

    # --- the early window requires an exact owner-authorized pair ----------
    #
    # The first physical early load took the kernel down: `list_del corruption /
    # LIST_POISON1` inside kernelsu.ko's own manager discovery
    # (my_actor <- search_manager <- track_throne <- kernelsu_init), DZIF boot
    # 5a7c2537, 2026-10-12. AGENTS.md 3.6.1 governs what follows: an operation
    # whose worst outcome is not a refusal needs an operation's evidence. The
    # owner authorized one repaired pair after the source fix and manual PASS.
    #
    # The guard is an ALLOWLIST of (fingerprint, ksud digest) pairs with a
    # authorized early load, and it must stay one. A denylist of the artefact
    # that panicked would let the next untested pair through by default, which
    # is the absence-as-permission shape section 2 forbids.
    allow_match = re.search(
        r"EARLY_LOAD_AUTHORIZED_ARTEFACTS\s*=\s*Set\.of\(([^;]*)\);",
        early_root_policy_src, flags=re.S)
    if not allow_match:
        fail("the early-load allowlist is gone; the early window would be open "
             "again for the artefact whose first physical load panicked the "
             "kernel")
    else:
        entries = allow_match.group(1)
        # Bound to bytes, not to a name (AGENTS.md 3.5). The daemon embeds the
        # exact kernelsu.ko, so its digest is the module's identity too - and
        # THIS digest is the one that panicked.
        panicked_ksud = ("f680f959472e994110eb1281d6aa47ed3cd934ae5775f5e9e378a2e9"
                         "46ae69e3")
        if panicked_ksud in entries.replace('"', "").replace("\n", "").replace(
                " ", "").replace("+", ""):
            fail("the ksud/kernelsu.ko pair whose first early load ended in a "
                 "kernel panic has been added to the early-load allowlist; "
                 "clearing it needs a corrected module, which arrives as a "
                 "different digest")
        if entries.strip() and "artefactKey(" not in entries:
            fail("the early-load allowlist holds raw entries that did not go "
                 "through artefactKey(); half a key would let a daemon cleared "
                 "on one firmware run on another")
    for required in ("private static final Set<String> EARLY_LOAD_AUTHORIZED_ARTEFACTS",
                     "public static boolean earlyLoadAuthorized(",
                     "ARTEFACT_NOT_AUTHORIZED"):
        if required not in early_root_policy_src:
            fail("the early-load suspension lost %r" % required)
    # --- no second, more permissive tier beside it --------------------------
    # AGENTS.md 3.6: "Restoring an at-own-risk opt-in is a policy decision for
    # the repository owner, made in the open. It is not a patch an agent applies
    # because a run is inconvenient." A "trial"/"experimental"/"at own risk"
    # list that permits an early dispatch on a pair nobody authorized is that
    # opt-in with a new name, and an automated review suggested exactly it on
    # PR #54. The circularity that suggestion was answering is real and was
    # fixed by naming what the one list gates - permission to attempt, with the
    # three-boot criterion promoting the dossier afterwards - not by adding a
    # tier.
    for banned in ("TRIAL_ARTEFACTS", "EXPERIMENTAL_ARTEFACTS",
                   "AT_OWN_RISK", "earlyLoadTrial", "ACCEPT_KERNEL_RISK"):
        if banned in early_root_policy_src:
            fail("a second, more permissive early-load tier (%r) is back beside "
                 "the authorized list; that is the at-own-risk opt-in 3.6 "
                 "removed, and only the repository owner may restore one" % banned)

    # Immutable. A list something can add to at run time is not a gate.
    if re.search(r"EARLY_LOAD_AUTHORIZED_ARTEFACTS\s*\.\s*(add|remove|clear)\(",
                 early_root_policy_src):
        fail("the early-load allowlist is mutated at run time; it may only be a "
             "compile-time statement about bytes that were physically validated")
    # Inside the one function both entry points call, and last, so that every
    # other gate stays falsifiable while the allowlist is empty.
    suspension_order = order(early_root_policy_src,
                             "READINESS_REFUSED, \"StageHop readiness is \"",
                             "if (!earlyLoadAuthorized(in.deviceFingerprint, in.ksudSha256))",
                             'return new Decision(true, ALLOW, "EARLY_ROOT_PREFLIGHT=PASS")')
    if suspension_order is None or suspension_order != sorted(suspension_order):
        fail("the early-load suspension is not the last check of the complete "
             "gate; placed earlier it makes the marker, SELinux and readiness "
             "gates unreachable while the allowlist is empty, and a gate that "
             "cannot fail is not a gate")
    # And refused at the arming too, so the owner is not told by a reboot.
    # The exact branch shape, not just the call: `if (false && !cleared(...))`
    # keeps the call text and defeats a guard that only looks for the name.
    if "if (!EarlyRootPolicy.earlyLoadAuthorized(" not in early_root_arm_src:
        fail("arming does not refuse on the early-load allowlist (the "
             "`if (!EarlyRootPolicy.earlyLoadAuthorized(` branch is gone or was "
             "short-circuited); the owner would spend a full reboot to be "
             "refused, on the artefact that panicked")
    arm_suspension = order(early_root_arm_src,
                           "EarlyRootPolicy.earlyLoadAuthorized(",
                           "scheduler.schedule(job)")
    if arm_suspension is None or arm_suspension != sorted(arm_suspension):
        fail("arming schedules the job before checking the early-load "
             "allowlist; a suspended artefact would leave a pending job behind")

    r["checks"]["early_root"] = {
        "job_service_exported": "true (BIND_JOB_SERVICE)",
        "run_service_exported": "false",
        "gate": "EarlyRootPolicy.evaluate in both entry points",
        "readiness_required": "NETWORKSTACK_READY",
        "attempts_per_boot": 1,
        "trace": "append-only, fsync'd, boot-scoped, bounded",
    }

    # --- Kotlin that no compiler in this environment will ever see -----------
    # There is no Kotlin compiler, SDK or Gradle here, so the signed release run is
    # the first thing that compiles this app - which means a syntax rule costs a
    # whole runner to discover. It already did: `claimSoftReboot` was written with an
    # expression body (`= try { ... }`) containing early `return`s, which Kotlin
    # prohibits, and :app:compileReleaseKotlin failed on it.
    #
    # This is the narrow static check for that exact rule. It is deliberately scoped
    # to the shapes an expression body actually takes in this codebase (`= try {`,
    # `= run {`, `= when {`, `= if (`), because a general Kotlin parser here would be
    # a new thing to be wrong about.
    expr_body = re.compile(
        r"^[ \t]*(?:private |internal |protected |public |override )*"
        r"fun\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*(?::[^=]+)?=\s*"
        r"(try|run|when|if)\b")
    kotlin_bodies = {}
    for name in ("AutoRootStore.kt", "DfrAutoRootService.kt", "DfrRootCoordinator.kt",
                 "DfrSoftRebootReceiver.kt", "RootNotifier.kt", "RootTransport.kt",
                 "MainActivity.kt", "KsudStage.kt", "StageHop.kt", "Diagnostics.kt",
                 "StageReceiver.kt", "DfrBootReceiver.kt", "TerminalActivity.kt",
                 "DfrEarlyBootProbe.kt", "DfrEarlyBootJobService.kt",
                 "EarlyBootProbeStore.kt", "DfrEarlyRoot.kt",
                 "DfrEarlyRootJobService.kt", "DfrEarlyRootService.kt",
                 "EarlyRootStore.kt", "EarlyRootEnv.kt"):
        try:
            kotlin_bodies[name] = dfr_source(name)
        except Exception:
            continue
    offenders = []
    for name, src in kotlin_bodies.items():
        kt_lines = code_only(src).split("\n")
        head = 0
        while head < len(kt_lines):
            if not expr_body.match(kt_lines[head]):
                head += 1
                continue
            # Brace-match forward from the function's opening line.
            depth = 0
            started = False
            cur = head
            while cur < len(kt_lines):
                depth += kt_lines[cur].count("{") - kt_lines[cur].count("}")
                if kt_lines[cur].count("{"):
                    started = True
                if started and depth <= 0:
                    break
                if cur > head and re.match(r"^[ \t]*return\b", kt_lines[cur]):
                    offenders.append("%s:%d" % (name, cur + 1))
                cur += 1
            head = max(cur, head + 1)
    if offenders:
        fail("expression-bodied Kotlin function contains a `return`, which the "
             "compiler prohibits (`Returns are prohibited for functions with an "
             "expression body`): %s. Nothing here can compile Kotlin, so this costs "
             "a signed release run to find. Use a block body." % ", ".join(offenders))
    r["checks"]["kotlin_expression_bodies"] = "%d file(s), no return inside one" % \
        len(kotlin_bodies)

    r["checks"]["auto_root"] = autoroot

    # stage1 must branch on the helper's intentional -E2BIG before creating the
    # positive marker or touching the namespace. An isolated dfm3 can never be
    # accepted by runAll.
    try:
        finit = s1_src.index("mov x8, #SYS_finit_module")
        expected = s1_src.index("cmn x26, #E2BIG", finit)
        helper = s1_src.index("create_mark mark_stage2", expected)
        namespace = s1_src.index("movl x0, (CLONE_NEWNS)", helper)
        if not finit < expected < helper < namespace:
            fail("stage1 finit_module/-E2BIG/HELPER_SUCCESS/namespace ordering drifted")
    except ValueError as ex:
        fail("stage1 post-root ordering token missing: %s" % ex)
    if "b.ne finit_unexpected" not in s1_src or "cmn x26, #ENODEV" not in s1_src:
        fail("stage1 no longer refuses unexpected finit_module results distinctly")
    if "mark1 == 1 && mark2 == 1 && mark3 == 1" not in exp_src_holder[0]:
        fail("runAll no longer requires helper+namespace+bind for bootstrap PASS")
    if "dfm3 is never final success" not in exp_src_holder[0]:
        fail("runAll no longer labels isolated dfm3 as incomplete")

    # --- the Kotlin copies of the Gate-D pins ------------------------------
    # The network_stack identity is COMPARED in Kotlin (Diagnostics/StageHop),
    # because that is where the observation exists - but the values are PINNED in
    # both profiles. Three copies of one fact drift silently, and Kotlin that
    # needs an Android runtime cannot be unit-tested here, so the guard is
    # static, per AGENTS.md 5.
    #
    # This also closes the older defect these fields had: they were pinned in both
    # profiles and read nowhere, so the profile advertised a boundary nothing
    # enforced. Now each is compared at run time AND tied to the pin here.
    KOTLIN_PINS = [
        ("network_stack_process", "StageHop.kt",
         r'NETWORK_STACK_PROCESS\s*=\s*"([^"]+)"'),
        ("network_stack_uid", "StageHop.kt",
         r'NETWORK_STACK_UID\s*=\s*(\d+)'),
        ("network_stack_context", "Diagnostics.kt",
         r'NETWORK_STACK_CONTEXT\s*=\s*"([^"]+)"'),
        ("network_stack_cap_eff", "Diagnostics.kt",
         r'NETWORK_STACK_CAP_EFF\s*=\s*"([^"]+)"'),
        # The scope test for the OEM boot-health policy. gate_target() already
        # implements it natively as anchor_hit = model_ok || device_ok; these are
        # the Kotlin mirror, and a drift here would either apply a Samsung-only
        # gate to unrelated hardware or stop applying it to the real target.
        ("model", "SoftRebootHealth.kt", r'TARGET_MODEL\s*=\s*"([^"]+)"'),
        ("device", "SoftRebootHealth.kt", r'TARGET_DEVICE\s*=\s*"([^"]+)"'),
    ]
    KOTLIN_DIR = os.path.join(ROOT, "app", "src", "main", "java",
                              "com", "polygraphene", "df", "reroot")

    def same_value(a, b):
        if a is None or b is None:
            return False
        try:
            return int(str(a), 0) == int(str(b), 0)
        except ValueError:
            return str(a) == str(b)

    kotlin_pins = {}
    for field, fname, pattern in KOTLIN_PINS:
        path = os.path.join(KOTLIN_DIR, fname)
        try:
            with open(path, encoding="utf-8") as f:
                src = f.read()
        except OSError as ex:
            fail("cannot read %s: %s" % (fname, ex))
            continue
        m = re.search(pattern, src)
        if not m:
            fail("%s no longer declares the constant mirroring %s; the profile "
                 "would pin a value nothing compares" % (fname, field))
            continue
        got = m.group(1)
        kotlin_pins[field] = got
        if not same_value(got, c.get(field)):
            fail("%s: Kotlin has %r but target_profile.c pins %r"
                 % (field, got, c.get(field)))
        if not same_value(got, j.get(field)):
            fail("%s: Kotlin has %r but zzic_profile.json pins %r"
                 % (field, got, j.get(field)))
    r["checks"]["kotlin_gate_d_pins"] = kotlin_pins

    # A pin tied to a constant nobody reads is the same dead weight in a new
    # place, so the signals that compare them must still be emitted.
    try:
        with open(os.path.join(KOTLIN_DIR, "Diagnostics.kt"), encoding="utf-8") as f:
            diag_src = f.read()
    except OSError as ex:
        fail("cannot read Diagnostics.kt: %s" % ex)
        diag_src = ""
    for signal in ("NETWORK_STACK_CAP_EFF=", "NATIVE_PAYLOAD_PACKAGED=",
                   "NATIVE_PAYLOAD_EXTRACTED="):
        if signal not in diag_src:
            fail("Diagnostics.kt no longer emits %s" % signal)
    if "NATIVE_LIBRARY_DISCOVERABLE=" in diag_src:
        fail("NATIVE_LIBRARY_DISCOVERABLE is back in Diagnostics.kt; with "
             "extractNativeLibs=false it has no reachable PASS, so it measures "
             "nothing - use NATIVE_PAYLOAD_PACKAGED / _EXTRACTED")

    # The run trace must reach logcat, or every "wait for X in logcat"
    # instruction in the docs is impossible to follow.
    try:
        with open(os.path.join(KOTLIN_DIR, "MainActivity.kt"), encoding="utf-8") as f:
            main_src = f.read()
    except OSError as ex:
        fail("cannot read MainActivity.kt: %s" % ex)
        main_src = ""
    m = re.search(r"private fun append\(s: String\) \{(.{0,900}?)\n    \}",
                  main_src, flags=re.S)
    if not m:
        fail("MainActivity.append() not found; the logcat mirror cannot be checked")
    # Strip comments first: `// Log.i(...)` still contains the text, so a
    # commented-out mirror passed a naive substring check. Found by sabotaging
    # this very guard.
    body = ""
    if m:
        body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
        body = re.sub(r"//[^\n]*", "", body)
    mirrored = bool(m and "Log.i(" in body)
    if m and not mirrored:
        fail("MainActivity.append() no longer mirrors to logcat; the run trace "
             "would exist only on screen")
    r["checks"]["append_mirrors_to_logcat"] = mirrored

    # --- C profile vs JSON profile agreement -------------------------------
    drift = []
    for k in SHARED_STRINGS:
        if k in j and c.get(k) != j[k]:
            drift.append("%s: C=%r json=%r" % (k, c.get(k), j[k]))
    for k in SHARED_INTS:
        if k in j and c.get(k) != j[k]:
            drift.append("%s: C=%r json=%r" % (k, c.get(k), j[k]))
    cap_c, cap_j = c.get("network_stack_cap_eff"), j.get("network_stack_cap_eff")
    if cap_j is not None and cap_c != int(str(cap_j), 0):
        drift.append("network_stack_cap_eff: C=%r json=%r" % (cap_c, cap_j))
    r["checks"]["profile_drift"] = drift or "none"
    for d in drift:
        fail("runtime profile and tools/zzic_profile.json disagree on %s" % d)

    # --- the JSON's two copies of each artefact hash must agree -------------
    targets = j.get("targets") or {}
    tdrift = []
    for path, field in TARGET_PATH_FIELDS.items():
        top = j.get(field)
        per_path = targets.get(path, "<absent>")
        if top != per_path:
            tdrift.append("%s: %s=%r targets[%s]=%r" % (field, field, top, path, per_path))
    r["checks"]["target_path_drift"] = tdrift or "none"
    for d in tdrift:
        fail("tools/zzic_profile.json disagrees with itself on %s" % d)

    # --- required artefact digests must be pinned --------------------------
    unpinned = [k for k in REQUIRED_ARTEFACT_HASHES if not c.get(k)]
    for k in unpinned:
        fail("%s is not pinned; the chain writes that artefact, and gate_hash() "
             "treats an unpinned required artefact as a hard FAIL" % k)
    r["checks"]["required_artefact_hashes"] = (
        "all pinned" if not unpinned else "MISSING %s" % ", ".join(unpinned))

    # --- vendor provenance is all-or-nothing -------------------------------
    missing_prov = [k for k in VENDOR_PROVENANCE_STRINGS if not c.get(k)]
    if c.get("vendor_mount_ro") not in (0, 1):
        missing_prov.append("vendor_mount_ro")
    for k in missing_prov:
        fail("vendor provenance anchor %s is not pinned; "
             "dfr_vendor_provenance_eval() refuses with FAIL_NO_PIN" % k)
    r["checks"]["vendor_provenance_anchors"] = (
        "all %d pinned" % (len(VENDOR_PROVENANCE_STRINGS) + 1)
        if not missing_prov else "MISSING %s" % ", ".join(missing_prov))

    # --- the vendor gate must not have regressed to a direct-hash-only check -
    #
    # The v2.0.2 gate hashed /vendor/lib64/libstagefrighthw.so directly, which
    # EACCESes in every domain this chain runs in. Reintroducing that call would
    # make the ZZIC path unrunnable again, and would do it silently, so name the
    # shape rather than trusting review to notice.
    if 'gate_hash(reporter, "ZZIC_VENDOR_ELF"' in exp_src_holder[0]:
        fail("exp.c hashes the vendor ELF directly again; that open(2) returns "
             "EACCES from system_server and network_stack on this firmware "
             "(use gate_vendor_provenance)")
    if "gate_vendor_provenance(" not in exp_src_holder[0]:
        fail("exp.c does not call gate_vendor_provenance(); the vendor artefact "
             "would be written with no provenance established")
    r["checks"]["vendor_gate"] = "gate_vendor_provenance"

    # --- the target's own casing is load-bearing ---------------------------
    if c.get("manufacturer") != "samsung":
        fail("manufacturer is %r; ro.product.manufacturer is lowercase "
             "'samsung' on this firmware and the compare is case-sensitive"
             % (c.get("manufacturer"),))

    # --- no runtime override of an UNVERIFIED Gate-G decision --------------
    #
    # Exact ZZIC support must never regain a marker that converts missing Gate-G
    # evidence into permission to proceed. Grepping only exp.c for one historical
    # token would be trivially defeated by a rename, or by putting the same
    # access() in any other runtime source, so reject the MECHANISM as well as the
    # spelling: no source that ships in DFReroot may reference a world-writable
    # /data/local/tmp path at all, since a marker read from one is the only shape
    # such an override can take. DFReroot has no legitimate use for that
    # directory, so any hit is either an override or needs the same scrutiny.
    runtime = sources_under(RUNTIME_ROOTS)
    chain = set(sources_under(CHAIN_ROOTS))
    hits = []
    for path in runtime:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError as ex:
            fail("cannot read runtime source %s: %s" % (rel(path), ex))
            continue
        rp = rel(path)
        if LEGACY_BYPASS_TOKEN in src:
            hits.append("%s references the removed Gate-G override token %r"
                        % (rp, LEGACY_BYPASS_TOKEN))
        if path in chain:
            for m in TMP_PATH_RE.finditer(src):
                hits.append("%s references a world-writable staging path: %s"
                            % (rp, m.group(0)))
    for h in hits:
        fail("possible Gate-G execution override: %s" % h)
    r["checks"]["runtime_sources_scanned"] = "%d (%d in the chain app)" % (
        len(runtime), len(chain))
    r["checks"]["unverified_module_override"] = "absent" if not hits else "present"

    # --- every page-cache stage must consult the module policy -------------
    #
    # The refusal is only as strong as its weakest entry point: patch_ko(),
    # patch_libc() and patch_cxx() are each reachable on their own (JNI natives,
    # StageReceiver transactions 1-3), so a policy enforced in one of them is not
    # enforced at all. Require the call in each.
    exp_src = exp_src_holder[0]
    unguarded = [s for s in PATCH_STAGES if not stage_calls_policy(exp_src, s)]
    for s in unguarded:
        fail("%s() does not call gate_module_policy(); a page-cache stage that "
             "skips Gate G re-opens the ZZIC path" % s)
    r["checks"]["module_policy_call_sites"] = (
        "all (%s)" % ", ".join(PATCH_STAGES) if not unguarded
        else "MISSING in %s" % ", ".join(unguarded)
    )

    # --- the ZZIC module must be reachable ONLY by identity -----------------
    # Kernel-family selection keys on (android_release, major, minor), and on
    # this firmware that is (15, 6, 6) - the same key as the generic upstream
    # android15-6.6 module that every other android15/6.6 device gets. The two
    # modules differ only in their __versions CRCs, so putting the ZZIC image
    # anywhere dfr_select_ko_image() can reach would offer a table built for THIS
    # kernel to a device that merely shares the family. That device would then
    # load a module whose CRCs disagree - refused by its kernel at insmod if it
    # is lucky, and this is not a gate the app can re-check afterwards.
    #
    # None of this is unit-testable: it is C that only runs on the device. So the
    # shape is asserted statically, per AGENTS.md section 5.
    exp_src = exp_src_holder[0]
    zzic_sel = {}
    zzic_sel["image_defined"] = "ko_image_zzic" in exp_src
    # The override must be the ZZIC identity branch, not family selection.
    zzic_sel["selected_by_identity"] = bool(
        re.search(r"cls == DFR_TARGET_S25U_ZZIC", exp_src)
        and re.search(r"ko\s*=\s*&ko_image_zzic\s*;", exp_src))
    # ko_images[] is the family table; the ZZIC image must not appear in it.
    table = re.search(r"ko_images\[\]\s*=\s*\{(.*?)\};", exp_src, re.S)
    zzic_sel["absent_from_family_table"] = bool(
        table and "zzic" not in table.group(1).lower())
    bundled_zzic = ko_name and "S938BXXUCZZIC" in str(ko_name)
    if bundled_zzic or zzic_sel["image_defined"]:
        if not zzic_sel["image_defined"]:
            fail("ko_filename names the exact-kernel module but exp.c defines no "
                 "ko_image_zzic to select it")
        if not zzic_sel["selected_by_identity"]:
            fail("exp.c does not assign ko = &ko_image_zzic inside the "
                 "DFR_TARGET_S25U_ZZIC branch; the exact-kernel module is "
                 "bundled but patch_ko would write the generic one")
        if not zzic_sel["absent_from_family_table"]:
            fail("the ZZIC module appears in ko_images[]; family selection "
                 "would offer a table built for this exact kernel to any "
                 "android15/6.6 device")
    if not table:
        fail("cannot find ko_images[] in exp.c; the family table guard is "
             "no longer checking anything")
    r["checks"]["zzic_module_selection"] = zzic_sel

    # --- the device collector must cover every compared field ---------------
    #
    # tools/zzic_collect.sh is what an operator actually runs on the device, and a
    # field it forgets to print is a field nobody checks until the app refuses with
    # a MISMATCH and no explanation. Require every property the runtime gate
    # compares to appear in the collector.
    try:
        with open(COLLECT_SH, encoding="utf-8") as f:
            collect_src = f.read()
    except OSError as ex:
        fail("cannot read %s: %s" % (rel(COLLECT_SH), ex))
        collect_src = ""
    missing = [k for k in COLLECTED_PROPS if k not in collect_src]
    for k in missing:
        fail("%s does not collect %s, a field dfr_classify_target() compares"
             % (rel(COLLECT_SH), k))
    r["checks"]["device_collector"] = (
        "covers all %d compared fields" % len(COLLECTED_PROPS) if not missing
        else "MISSING %s" % ", ".join(missing)
    )

    # --- Gate C/D signal regressions ---------------------------------------
    #
    # These live in Kotlin and need an Android runtime to execute, so they
    # cannot be unit-tested off-device. What CAN be checked offline is that the
    # signals the v2.0.2-zzic physical run established are still emitted, and
    # that the shapes that run proved are still the ones invoked. Each entry is
    # (file, required substring, why it matters).
    signals = [
        (os.path.join(ROOT, "app", "src", "main", "java", "com", "polygraphene",
                      "df", "reroot", "StageHop.kt"),
         "parameterCount == 12",
         "Android 17 / One UI 9 exposes scheduleReceiver/12; that shape was "
         "observed physically and must stay the one invoked"),
        (os.path.join(ROOT, "app", "src", "main", "java", "com", "polygraphene",
                      "df", "reroot", "StageHop.kt"),
         "mProcessNames",
         "getProcessRecordLocked is ABSENT on Android 17; the mProcessNames "
         "fallback is the only path that resolved the ProcessRecord"),
        (os.path.join(ROOT, "app", "src", "main", "java", "com", "polygraphene",
                      "df", "reroot", "StageHop.kt"),
         "PROCESS_LOOKUP=",
         "the lookup must end on an explicit PASS/FAIL verdict, not on a bare "
         "UNKNOWN after a fallback has already succeeded"),
        (os.path.join(ROOT, "app", "src", "main", "java", "com", "polygraphene",
                      "df", "reroot", "StageReceiver.kt"),
         "EXTRA_DIAG",
         "the remote boundary's own evidence must travel back to the UI, not "
         "live only in logcat"),
        (os.path.join(ROOT, "app", "src", "main", "java", "com", "polygraphene",
                      "df", "reroot", "Diagnostics.kt"),
         "PROCESS_LOOKUP_PRIMARY=",
         "an absent primary lookup must be reported as UNAVAILABLE, which is "
         "not a blocker, rather than as a bare UNKNOWN"),
    ]
    missing_signals = []
    for path, needle, why in signals:
        try:
            with open(path, encoding="utf-8") as f:
                src = f.read()
        except OSError as ex:
            fail("cannot read %s: %s" % (rel(path), ex))
            continue
        if needle not in src:
            missing_signals.append("%s no longer contains %r: %s"
                                   % (rel(path), needle, why))
    for m in missing_signals:
        fail("Gate C/D signal regression: %s" % m)
    r["checks"]["gate_cd_signals"] = ("all %d present" % len(signals)
                                      if not missing_signals
                                      else "MISSING %d" % len(missing_signals))

    r["status"] = "PASS" if not r["violations"] else "FAIL"
    return r


def human(r):
    L = ["=== profile / module binding audit (dossier section 39) ==="]
    ck = r["checks"]
    L.append("ko_verified    : %s" % ck.get("ko_verified"))
    L.append("ko_filename         : %s" % (ck.get("ko_filename") or "<none>"))
    L.append("ko_sha256 (pinned)  : %s" % (ck.get("ko_sha256_pinned") or "<none>"))
    if "ko_sha256_actual" in ck:
        L.append("ko_sha256 (bundled) : %s" % ck["ko_sha256_actual"])
    L.append("ZZIC_MODULE_BINDING : %s" % ck.get("ZZIC_MODULE_BINDING", "n/a"))
    if "ZZIC_MODULE_VERDICT" in ck:
        # Print the verdict AND the table that decided it. A Module.symvers names
        # no kernel, so the digest is the only record of which one was used.
        L.append("  ko_audit verdict  %s, coverage %s"
                 % (ck["ZZIC_MODULE_VERDICT"], ck.get("ZZIC_MODULE_COVERAGE")))
        L.append("  against symvers   %s" % ck.get("ZZIC_MODULE_SYMVERS"))
    L.append("ZZIC_KSUD_BINDING   : %s" % ck.get("ZZIC_KSUD_BINDING", "n/a"))
    if ck.get("ksud_sha256_actual"):
        L.append("  assets/ksud       %s (%s bytes)"
                 % (ck["ksud_sha256_actual"], ck.get("ksud_size_actual")))
    L.append("stage2 --stage-from : %s" % ck.get("stage2_argv_stage_from", "n/a"))
    for base, cov in sorted((ck.get("modversion_coverage") or {}).items()):
        L.append("  modversions %-28s %s" % (base, cov))
    L.append("profile drift       : %s" % ck.get("profile_drift"))
    L.append("runtime sources     : %s scanned for an execution override"
             % ck.get("runtime_sources_scanned"))
    L.append("Gate-G override     : %s" % ck.get("unverified_module_override"))
    L.append("policy call sites   : %s" % ck.get("module_policy_call_sites"))
    L.append("device collector    : %s" % ck.get("device_collector"))
    L.append("targets[] drift     : %s" % ck.get("target_path_drift"))
    L.append("required hashes     : %s" % ck.get("required_artefact_hashes"))
    L.append("vendor provenance   : %s" % ck.get("vendor_provenance_anchors"))
    L.append("vendor gate         : %s" % ck.get("vendor_gate"))
    L.append("gate C/D signals    : %s" % ck.get("gate_cd_signals"))
    L.append("Kotlin Gate-D pins  : %d tied to both profiles"
             % len(ck.get("kotlin_gate_d_pins") or {}))
    L.append("append -> logcat    : %s" % ck.get("append_mirrors_to_logcat"))
    zs = ck.get("zzic_module_selection") or {}
    if zs:
        L.append("ZZIC ko selection   : %s"
                 % ("by identity, absent from the family table"
                    if all(zs.values())
                    else "PROBLEM %s" % zs))
    L.append("")
    for v in r["violations"]:
        L.append("  [x] %s" % v)
    L.append("status              : %s" % r["status"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit()
    print(json.dumps(r, indent=2) if a.json else human(r))
    return 0 if r["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
