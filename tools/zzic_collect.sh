#!/system/bin/sh
# zzic_collect.sh - one read-only pass that collects everything docs/HANDOFF.md
# asks for from the device. Run it in Termux (or `adb shell sh zzic_collect.sh`).
#
#   sh zzic_collect.sh > zzic-identity.txt 2>&1
#
# It WRITES NOTHING and needs no root for the identity and crash_dump64 sections.
# /proc/kallsyms is root-only and is skipped with a clear note when `su` is absent.
#
# Why this exists: the S25U_ZZIC profile compares twelve identity fields
# EXACTLY and case-sensitively. If a single one differs, dfr_classify_target()
# returns MISMATCH and the app refuses everything - so the values below are what
# decide whether the profile can be used at all, before any of the gate work
# matters. Compare this output against tools/zzic_profile.json.

echo "=== DFReroot ZZIC evidence collection ==="
echo "collected_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)"
echo

# ---------------------------------------------------------------- Gate A input
# Every field dfr_classify_target() compares, in profile order, so the output can
# be read straight down against the profile. Blank means the property is unset,
# which never matches (dfr_streq treats NULL/absent as "no value").
echo "--- identity (Gate A: all twelve must match EXACTLY, case-sensitive) ---"
for p in \
    ro.product.manufacturer \
    ro.product.model \
    ro.product.device \
    ro.build.version.sdk \
    ro.build.version.release \
    ro.build.display.id \
    ro.build.fingerprint \
    ro.product.cpu.abi
do
    printf '%-32s = %s\n' "$p" "$(getprop "$p")"
done
printf '%-32s = %s\n' "uname -r (kernel_release)" "$(uname -r)"
printf '%-32s = %s\n' "uname -v (kernel_version)" "$(uname -v)"
printf '%-32s = %s\n' "uname -m (kernel_arch)" "$(uname -m)"
printf '%-32s = %s\n' "page_size" "$(getconf PAGESIZE 2>/dev/null || echo UNKNOWN)"
echo
echo "Note: kernel_version is a build timestamp (#1 SMP PREEMPT <date>). It is the"
echo "field most likely to differ after any firmware rebuild, and a difference is a"
echo "MISMATCH, not a near miss."
echo

# ------------------------------------------------------- Gate B: crash_dump64
# The pristine SHA-256 of crash_dump64. It IS pinned as of v2.0.3-zzic
# (9249d664...), captured on this device; this section re-checks it. Capture it
# BEFORE ever running the chain - once a run has patched the page cache the value
# is no longer pristine, and a hash taken then would pin corruption as the
# expected state. A value here that differs from the pinned one means the
# firmware changed, and the chain must refuse until the profile is re-derived.
echo "--- crash_dump64 (Gate B: must equal the pinned crashdump_sha256) ---"
CD=/apex/com.android.runtime/bin/crash_dump64
if [ -r "$CD" ]; then
    echo "path   = $CD"
    echo "size   = $(wc -c < "$CD" 2>/dev/null | tr -d ' ')"
    HASH=$(sha256sum "$CD" 2>/dev/null | cut -d' ' -f1)
    if [ -n "$HASH" ]; then
        echo "sha256 = $HASH"
        echo
        echo "Pin this in BOTH files (the CI drift check requires they agree):"
        echo "  app/src/main/jni/target_profile.c -> .crashdump_sha256 = \"$HASH\","
        echo "  tools/zzic_profile.json           -> \"crashdump_sha256\": \"$HASH\","
        echo "  tools/zzic_profile.json           -> targets[\"$CD\"]: \"$HASH\""
    else
        echo "sha256 = UNAVAILABLE (no sha256sum on PATH)"
        echo "  Termux: pkg install coreutils     adb: use 'adb shell sha256sum $CD'"
    fi
else
    echo "path   = $CD"
    echo "sha256 = UNREADABLE (not present, or denied to this uid)"
    echo "  Retry under temp root: su -c \"sha256sum $CD\""
fi
echo

# ------------------------------------------------- Gate B: vendor provenance
# /vendor/lib64/libstagefrighthw.so is NOT openable from the domain DFReroot runs
# in (EACCES from u:r:system_server:s0 and u:r:network_stack:s0, observed in the
# v2.0.2-zzic physical run), so its identity is established through the AVB chain
# the pinned digest was captured under instead of a direct runtime hash. Every
# value below is part of that chain and every one of them is compared.
echo "--- vendor provenance (Gate B: ZZIC_VENDOR_PROVENANCE inputs) ---"
for p in \
    ro.boot.verifiedbootstate \
    ro.boot.vbmeta.device_state \
    ro.boot.flash.locked \
    ro.boot.veritymode \
    ro.boot.vbmeta.digest \
    ro.boot.vbmeta.avb_version \
    ro.boot.vbmeta.hash_alg
do
    printf '%-32s = %s\n' "$p" "$(getprop "$p")"
done
printf '%-32s = %s\n' "/vendor mount" \
    "$(grep -m1 ' /vendor ' /proc/self/mountinfo 2>/dev/null || echo UNKNOWN)"
VF=/vendor/lib64/libstagefrighthw.so
printf '%-32s = %s\n' "vendor elf" "$VF"
if [ -r "$VF" ]; then
    printf '%-32s = %s\n' "  readable as uid $(id -u)" "yes"
    printf '%-32s = %s\n' "  size" "$(wc -c < "$VF" 2>/dev/null | tr -d ' ')"
    printf '%-32s = %s\n' "  sha256" "$(sha256sum "$VF" 2>/dev/null | cut -d' ' -f1)"
else
    printf '%-32s = %s\n' "  readable as uid $(id -u)" "NO (expected outside u:r:ksu:s0)"
    echo "  Capture it from a root shell: su -c \"sha256sum $VF\""
fi
echo
echo "The seven ro.boot.* values plus the /vendor fstype (erofs) and ro flag are"
echo "ALL compared. Any single divergence is ZZIC_VENDOR_PROVENANCE=FAIL_CHAIN and"
echo "the chain refuses before any page-cache write."
echo

# ----------------------------------------------------------- per-boot anchoring
# Evidence from different boots must never be combined into one successful chain,
# so every capture carries the boot it came from.
echo "--- boot_id (states from different boots must never be combined) ---"
echo "boot_id = $(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo UNKNOWN)"
echo

# ----------------------------------------------------------------- Gate D input
echo "--- network_stack (Gate D: the hop target must be running) ---"
NS=$(ps -A -o PID,USER,NAME 2>/dev/null | grep -i networkstack | grep -v grep)
if [ -n "$NS" ]; then
    echo "$NS"
else
    echo "no com.android.networkstack.process found in ps output."
    echo "  It is started on demand; toggle Wi-Fi or mobile data and re-run."
    echo "  StageHop cannot find a ProcessRecord for a process that is not running."
fi
echo

# ----------------------------------------------------------------- Gate G input
# The module ABI question. Module.symvers CANNOT be taken from a running device -
# it is a kernel BUILD artefact - so kallsyms is existence evidence only, for the
# two symbols the module resolves at runtime rather than importing.
echo "--- Gate G inputs (module ABI) ---"
echo "CONFIG_MODVERSIONS: the ZZIC kernel has it enabled, and the bundled"
echo "  dirtyfrag-android15-6.6.ko ships an EMPTY __versions table, so no symbol-CRC"
echo "  agreement can be established offline. Verdict stays UNVERIFIED."
echo
echo "Module.symvers is produced by building the kernel; it cannot be read off a"
echo "running device. Without it Gate G cannot reach COMPATIBLE, and there is no"
echo "runtime override - so the chain will refuse regardless of the hash above."
echo
if [ "$(id -u)" = "0" ]; then
    echo "running as uid 0: dumping runtime-resolved symbol existence"
    for s in kallsyms_lookup_name selinux_state; do
        L=$(grep -w "$s" /proc/kallsyms 2>/dev/null | head -1)
        printf '  %-24s %s\n' "$s" "${L:-NOT FOUND in /proc/kallsyms}"
    done
    echo
    echo "  Full capture for tools/ko_audit.py --kallsyms:"
    echo "    su -c 'cat /proc/kallsyms' > kallsyms.txt"
else
    echo "not uid 0: /proc/kallsyms is root-only and was skipped."
    echo "  Under temp root: su -c 'cat /proc/kallsyms' > kallsyms.txt"
fi
echo

echo "=== end ==="
echo
echo "Next, per docs/HANDOFF.md:"
echo "  1. Diff the identity block against tools/zzic_profile.json. Any single"
echo "     difference means the profile does not describe this device; fix the"
echo "     profile from observed values, never the other way round."
echo "  2. Pin crashdump_sha256 in both files and rebuild."
echo "  3. Capture the run:  logcat -c && logcat -s DFReroot DirtyFrag | tee zzic-run.log"
echo "     The line that unblocks StageHop is [DFR][AMS] scheduleReceiver/<n> params=[...]"
echo "  4. Gate G still refuses. That is the remaining blocker, and it needs a"
echo "     kernel build artefact, not a device capture."
