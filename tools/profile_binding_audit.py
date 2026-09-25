#!/usr/bin/env python3
"""
Profile-to-module cryptographic binding audit (dossier section 39).

`ko_zzic_verified` is a boolean, and a boolean is not evidence. This tool
enforces, in CI, the same invariant the runtime enforces in patch_ko():

    ko_zzic_verified == 1
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
# ko_zzic_verified=1, so this tool also guards the rule that verdict rests on.
sys.path.insert(0, HERE)
import ko_audit  # noqa: E402
PROFILE_C = os.path.join(ROOT, "app", "src", "main", "jni", "target_profile.c")
JNI_DIR = os.path.join(ROOT, "app", "src", "main", "jni")
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
        lits = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
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
    verified = c.get("ko_zzic_verified")
    ko_sha = c.get("ko_sha256")
    ko_name = c.get("ko_filename")
    r["checks"]["ko_zzic_verified"] = verified
    r["checks"]["ko_filename"] = ko_name
    r["checks"]["ko_sha256_pinned"] = ko_sha

    if verified not in (0, 1):
        fail("ko_zzic_verified is %r; expected 0 or 1" % (verified,))
    elif verified == 1:
        if not ko_sha:
            fail("ko_zzic_verified=1 but ko_sha256 is not pinned "
                 "(a boolean is not evidence)")
        if not ko_name:
            fail("ko_zzic_verified=1 but ko_filename is not set")
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
                        fail("ko_zzic_verified=1 but %s cannot be audited "
                             "against the derived ZZIC table: %s" % (ko_name, ex))
                        full = None
                    if full is not None:
                        got = full.get("MODULE_VS_ZZIC_KERNEL")
                        cov = full.get("MODVERSION_COVERAGE")
                        r["checks"]["ZZIC_MODULE_VERDICT"] = got
                        r["checks"]["ZZIC_MODULE_COVERAGE"] = cov
                        if got != "COMPATIBLE":
                            fail("ko_zzic_verified=1 but the bundled %s audits "
                                 "%r against the derived ZZIC table, not "
                                 "COMPATIBLE" % (ko_name, got))
                        if full.get("provenance_violations"):
                            fail("ko_zzic_verified=1 but the derived table's "
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
            fail("ko_zzic_verified=0 but ko_sha256 is pinned (%s); "
                 "a stale digest reads as evidence it is not" % ko_sha)
        if ko_name:
            fail("ko_zzic_verified=0 but ko_filename is set (%s)" % ko_name)
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

    main_kt_path = os.path.join(ROOT, "app", "src", "main", "java", "com",
                                "polygraphene", "df", "reroot", "MainActivity.kt")
    try:
        with open(main_kt_path, encoding="utf-8") as f:
            main_src_holder = [f.read()]
    except OSError as ex:
        fail("cannot read MainActivity.kt: %s" % ex)
        main_src_holder = [""]

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
    for signal in (
            "val success = runResult == 0 && postRootComplete",
            "PostRootStatus.evaluate(record, bootId, liveSelinux)",
            "ROOT_RESULT=SUCCESS"):
        if signal not in main_src:
            fail("MainActivity post-root fail-closed signal missing: %r" % signal)
    r["checks"]["post_root_contract"] = java_contract

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
    L.append("ko_zzic_verified    : %s" % ck.get("ko_zzic_verified"))
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
