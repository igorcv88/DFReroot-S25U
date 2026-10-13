#!/system/bin/sh
# Collect the evidence for ONE early-root boot, per docs/EARLY_ROOT.md section 8.
#
# Run it as soon as possible in a boot where Early Integrated Root ran, with
# root available (su). Everything lands in /sdcard/Download/.
#
# It reads only. It arms nothing, clears nothing and writes nothing outside the
# output file.
#
#   su -c 'sh /sdcard/Download/earlyroot_collect_pass.sh'
#
# Why each block is here, because a collection nobody can account for is not
# evidence:
#
#  - the panic/reboot records FIRST. AGENTS.md 3.6.1: on this firmware they
#    survive at ro.debug_level=0x4f4c while pstore and `logcat -L` are empty.
#
#    ONE RUN OF THIS SCRIPT CANNOT CLOSE THAT CRITERION, and the workflow has to
#    say so. Section 8 requires no _KP entry "in that boot or the one after it",
#    and a snapshot taken at 2 minutes of boot N cannot speak for a panic at 40
#    minutes of boot N, nor for boot N+1 at all. So a boot's packet is complete
#    only when the NEXT boot's collection also comes back with no _KP
#    attributable to it: three accepted boots need FOUR runs of this script.
#    Codex caught the premature "one pass completes it" wording on PR #63;
#  - the trace with its per-step elapsed_ms, which is what turns "root before
#    BOOT_COMPLETED" from a claim into an ordering two numbers can be compared
#    on;
#  - the post-root record and a live SELinux read, independently of the chain's
#    own verdict;
#  - `dev.bootcomplete` and `dev.platform_bootcomplete`. These are NOT for this
#    milestone. They are the measurement AGENTS.md 3.6.2 says nobody has taken
#    on this firmware, and they gate the whole second half of the product goal:
#    a baseline from a boot where NOTHING tore userspace down. This is that
#    boot. Without the pair, every design for the module/soft-reboot handshake
#    is a guess.

OUT=/sdcard/Download/dfr_earlyroot_pass_$(date +%Y%m%d_%H%M%S).txt
say() { echo "$@" >> "$OUT"; }
# stderr is CAPTURED, never discarded, and the exit status is recorded. A block
# that failed and a block that was empty look identical otherwise, and most of
# these blocks exist to establish the ABSENCE of something (AGENTS.md 2: an
# absence is only evidence when the reader can tell it from a failed read).
show() {
    say "--- $1 ---"
    shift
    "$@" >> "$OUT" 2>&1
    say "[exit_status=$?]"
    say ""
}

say "=== DFReroot early-root boot evidence ==="
say "collected_wallclock=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "collected_uptime_s=$(cut -d' ' -f1 /proc/uptime)"
say "uid=$(id -u)"
say ""
say "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
say ""

# 1. Panic and reboot records, before anything else.
show "sec_hw_param/extra_info" cat /sys/class/sec/sec_hw_param/extra_info
# AGENTS.md 3.6.1 names this one as the carrier of the surrounding kernel log,
# and the collector was not reading it.
show "sec_hw_param/extrc_info" cat /sys/class/sec/sec_hw_param/extrc_info
# These two come and go: present on 2026-10-12 after the panic, ENOENT in a
# clean boot. show() records the exit status, so "absent" and "unreadable" stay
# distinguishable - and neither is proof of a clean boot on its own.
show "reset_summary (may be absent)" cat /proc/reset_summary
show "reset_history (may be absent)" cat /proc/reset_history
# The one block whose whole purpose is to prove an ABSENCE, so it is the one
# block that must never report a failed read as a clean boot.
#
# `ls ... 2>/dev/null | grep SYSTEM_LAST_KMSG` produced an empty section for an
# unreadable directory AND for a boot with no panic entry - the same bytes for
# "no panic happened" and "nobody could look". Codex caught it on PR #63, and it
# is the ENOENT-versus-other-errno discipline this repository enforces in code,
# missing from the script that collects the evidence for it.
#
# So: the listing is taken once into a variable, its status is recorded, and the
# three outcomes are named apart.
say "--- dropbox SYSTEM_LAST_KMSG (_KP = panic, _RP = ordinary reboot) ---"
DROPBOX_LS=$(ls -l /data/system/dropbox 2>&1)
DROPBOX_STATUS=$?
say "[ls exit_status=$DROPBOX_STATUS]"
if [ "$DROPBOX_STATUS" -ne 0 ]; then
    say "DROPBOX=UNREADABLE - the listing failed, so this boot's panic state is"
    say "NOT established. This is a refusal, not a clean boot. Re-run with su."
    say "$DROPBOX_LS"
else
    DROPBOX_KMSG=$(echo "$DROPBOX_LS" | grep SYSTEM_LAST_KMSG)
    if [ -z "$DROPBOX_KMSG" ]; then
        say "DROPBOX=LISTED_NO_KMSG_ENTRY - the directory was read and holds no"
        say "SYSTEM_LAST_KMSG entry at all. Absence established by a successful read."
    else
        say "DROPBOX=LISTED_WITH_ENTRIES - read the _KP/_RP suffix on each:"
        say "$DROPBOX_KMSG"
    fi
fi
say ""
say "ro.boot.bootreason=$(getprop ro.boot.bootreason)"
say "sys.boot.reason=$(getprop sys.boot.reason)"
say ""

# 2. The chain's own durable records for this boot.
show "early-root trace (per-step elapsed_ms)" cat /data/system/dfreroot-early-root-trace
show "early-root journal" cat /data/system/dfreroot-early-root-journal
show "early-root cycle" cat /data/system/dfreroot-early-root-cycle
show "early-root arm" cat /data/system/dfreroot-early-root-arm
show "early-root incident log" cat /data/system/dfreroot-early-root-incident
show "post-root record" cat /data/system/dfreroot-post-root
show "auto-root journal" cat /data/system/dfreroot-autoroot-journal
# The probe's real record names. The first revision of this script read
# "dfreroot-early-boot-probe", which does not exist - EarlyBootProbeStore uses
# the -early-job- prefix - so the 2026-10-13 packet reported an absence that was
# a wrong path rather than a missing record.
show "early-job probe" cat /data/system/dfreroot-early-job-probe
show "early-job arm" cat /data/system/dfreroot-early-job-arm
show "early-job callback" cat /data/system/dfreroot-early-job-callback
show "locked-boot marker" cat /data/system/dfreroot-locked-boot-marker

# --- who tore userspace down, if anybody in THIS app did ------------------
# The 2026-10-13 PASS boot had both boot broadcasts re-delivered 66.3 min in,
# under the same boot_id - the signature of a framework restart - and neither
# the capture nor the owner could say what caused it. It stays unattributed.
#
# These three are what would attribute the next one. DFReroot's soft-reboot path
# writes phase=CLAIMED to the lock BEFORE the daemon is ever invoked
# (AGENTS.md 3.6.1), traces each privileged step, and records the firmware's
# boot-health verdict afterwards. So: records present and naming this boot means
# this app asked for it; records absent or naming an earlier boot means it did
# not, and the restart came from somewhere else. Either answer is worth more
# than the question, and the chain never reaches this path from the early
# trigger - which is itself the thing being checked.
show "soft-reboot lock" cat /data/system/dfreroot-softreboot-lock
show "soft-reboot trace" cat /data/system/dfreroot-softreboot-trace
show "soft-reboot health" cat /data/system/dfreroot-softreboot-health

# 3. The verdict's independent half.
say "selinux_enforce=$(cat /sys/fs/selinux/enforce)"
say "sys.boot_completed=$(getprop sys.boot_completed)"
say "service.bootanim.exit=$(getprop service.bootanim.exit)"
say ""

# 4. The AGENTS.md 3.6.2 baseline: a boot where nothing restarted userspace.
say "=== boot-health properties (3.6.2 baseline, no userspace teardown) ==="
say "dev.bootcomplete=$(getprop dev.bootcomplete)"
say "dev.platform_bootcomplete=$(getprop dev.platform_bootcomplete)"
say "init.svc.zygote=$(getprop init.svc.zygote)"
say "init.svc.bootchecker=$(getprop init.svc.bootchecker)"
say "sys.bootstat.first_boot_completed=$(getprop sys.bootstat.first_boot_completed)"
show "bootchecker.rc (the rules that key on these)" cat /system/etc/init/bootchecker.rc
show "rollback timeline (CrashRecovery's own view)" dumpsys rollback
say ""

# 5. What the root actually is, from the daemon rather than from our verdict.
show "ksud version" /data/adb/ksud --version
show "lsmod" lsmod
say "ksu_module_dir:"
ls -l /data/adb/modules 2>&1 >> "$OUT"
say ""

echo "$OUT"
