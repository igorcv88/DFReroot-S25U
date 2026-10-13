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
#    survive at ro.debug_level=0x4f4c while pstore and `logcat -L` are empty,
#    and the acceptance criterion requires NO _KP DropBox entry in this boot or
#    the next one;
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
show() { say "--- $1 ---"; shift; "$@" >> "$OUT" 2>&1; say ""; }

say "=== DFReroot early-root boot evidence ==="
say "collected_wallclock=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "collected_uptime_s=$(cut -d' ' -f1 /proc/uptime)"
say "uid=$(id -u)"
say ""
say "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
say ""

# 1. Panic and reboot records, before anything else.
show "sec_hw_param/extra_info" cat /sys/class/sec/sec_hw_param/extra_info
show "reset_summary" cat /proc/reset_summary
show "reset_history" cat /proc/reset_history
say "--- dropbox SYSTEM_LAST_KMSG (_KP = panic, _RP = ordinary reboot) ---"
ls -l /data/system/dropbox 2>/dev/null | grep SYSTEM_LAST_KMSG >> "$OUT" 2>&1
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
show "early-boot probe" cat /data/system/dfreroot-early-boot-probe

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
