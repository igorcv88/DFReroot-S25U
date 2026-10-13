#!/system/bin/sh
# Why this exists, and what it is allowed to conclude.
#
# The Early Integrated Root job has been called back punctually (14.6-17.0 s on
# four boots) and wildly late (299 s, 334 s, 521 s) with no change in the app's
# JobInfo. The delay happens BEFORE onStartJob's first statement, so no
# instrumentation inside DFReroot can see it (docs/HANDOFF.md). The scheduler's
# own state is the only place the answer can be.
#
# Two hypotheses remain after force-batching was refuted from AOSP source
# (JobSchedulerService.java: shouldForceBatchJob carries
# `&& job.getEffectiveStandbyBucket() != EXEMPTED_INDEX` in BOTH branches, and
# dumpsys puts this job in EXEMPTED):
#
#   (a) READY-AND-DEFERRED. The job's constraints are satisfied, it sits in the
#       pending queue, and the scheduler does not run it. Then the cause is on
#       the scheduler side - concurrency slots, standby, quota, an OEM change -
#       and the next step is to read which.
#
#   (b) NOT-READY. TIMING_DELAY is unsatisfied because the restored earliest-run
#       time is in the future. AOSP converts a persisted latency/deadline from
#       wallclock at restore (`nowElapsed + max(storedRtc - nowWallclock, 0)`),
#       and TimeController arms the delay with
#       `AlarmManager.ELAPSED_REALTIME` + `WINDOW_HEURISTIC` - a NON-WAKEUP,
#       INEXACT alarm that the framework may coalesce freely. Then the cause is
#       how DFReroot expresses its timing, which is ours to change.
#
# These two have different fixes and NOTHING in the logs collected so far
# distinguishes them. One field does: the job's satisfied/unsatisfied
# constraints and its earliest run time, sampled while the wait is happening.
#
# Run it as early in the boot as the device allows (Termux, directly or through
# rish; no root required, no ADB). Everything lands in /sdcard/Download.
#
#   sh earlyroot_job_probe.sh            # ~10 min, one sample every 5 s
#   sh earlyroot_job_probe.sh 1200 10    # or: duration_s interval_s
#
# It only reads. It schedules nothing, cancels nothing and changes no setting.

PKG=com.polygraphene.df.reroot
JOB=1145459282
NS=dfr-early-root
DURATION=${1:-600}
INTERVAL=${2:-5}
OUT=/sdcard/Download/dfr_job_probe_$(date +%Y%m%d_%H%M%S).txt

say() { echo "$@" >> "$OUT"; }

say "=== DFReroot early-root job probe ==="
say "started_wallclock=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "started_uptime_s=$(cut -d' ' -f1 /proc/uptime)"
say "duration_s=$DURATION interval_s=$INTERVAL"
say ""
# The boot's own identity and the two properties the policy gates on. A sample
# series that cannot be placed in a boot proves nothing (AGENTS.md 3.8).
say "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
say "sys.boot_completed=$(getprop sys.boot_completed)"
say "service.bootanim.exit=$(getprop service.bootanim.exit)"
say "dev.bootcomplete=$(getprop dev.bootcomplete)"
say "dev.platform_bootcomplete=$(getprop dev.platform_bootcomplete)"
say "ro.boot.bootreason=$(getprop ro.boot.bootreason)"
say ""
# The arm record is what decides whether hypothesis (b) is even arithmetically
# possible: if armed_wallclock_ms + minimum_latency_ms is already in the past at
# restore, the restored earliest-run time is clamped to now and no delay alarm
# is involved at all. Unreadable without root on some boots - that is itself
# worth recording rather than inferring.
say "--- arm record (may be unreadable without root) ---"
cat /data/system/dfreroot-early-root-arm 2>&1 >> "$OUT"
say ""
say "--- cycle record ---"
cat /data/system/dfreroot-early-root-cycle 2>&1 >> "$OUT"
say ""
say "--- trace ---"
cat /data/system/dfreroot-early-root-trace 2>&1 >> "$OUT"
say ""
say "now_wallclock_ms=$(date +%s%3N)"
say ""

END=$(( $(cut -d. -f1 /proc/uptime) + DURATION ))
N=0
while [ "$(cut -d. -f1 /proc/uptime)" -lt "$END" ]; do
    N=$((N + 1))
    say "########## sample $N  uptime_s=$(cut -d' ' -f1 /proc/uptime)  $(date -u +%H:%M:%S) ##########"
    # THE discriminating read. Required/Satisfied/Unsatisfied constraints plus
    # the run-time window, for our job only.
    dumpsys jobscheduler 2>/dev/null \
        | grep -A 30 "$PKG" \
        | grep -iE "JOB #|$JOB|constraint|Earliest run time|Latest run time|run time|Enqueue|bucket|Ready|pending|active|readyNow|satisfied" \
        >> "$OUT" 2>&1
    say "--- cmd get-job-state ---"
    cmd jobscheduler get-job-state -n "$NS" "$PKG" "$JOB" >> "$OUT" 2>&1
    # The alarm half of hypothesis (b): TimeController's delay alarm is
    # non-wakeup and inexact, so its trigger time is the thing to read.
    say "--- TimeController alarms ---"
    dumpsys alarm 2>/dev/null | grep -iE "job\.delay|job\.deadline|\*job\*" >> "$OUT" 2>&1
    say ""
    sleep "$INTERVAL"
done

say "=== finished uptime_s=$(cut -d' ' -f1 /proc/uptime) samples=$N ==="
# The scheduler's whole state, once, at the end: the per-job sections above are
# the answer, this is the context for whichever one it turns out to be.
say ""
say "=== full jobscheduler dump (tail) ==="
dumpsys jobscheduler >> "$OUT" 2>&1
echo "$OUT"
