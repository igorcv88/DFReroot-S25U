#!/system/bin/sh
# Why this exists, and what it is allowed to conclude.
#
# The Early Integrated Root job has been called back punctually (14.6-17.0 s on
# four boots) and wildly late (299 s, 334 s, 521 s) with no change in the app's
# JobInfo. The delay happens BEFORE onStartJob's first statement, so no
# instrumentation inside DFReroot can see it (docs/HANDOFF.md). The scheduler's
# own state is the only place the answer can be.
#
# HALF-RESOLVED on 2026-10-13, by this script's own first run: it is (a),
# ready-and-deferred. The dump showed `Unsatisfied constraints:` EMPTY, with
# TIMING_DELAY satisfied at ~16.5 s and DEADLINE at ~26.7 s, and both jobs were
# dispatched at 701.7 s. So the wait is not in the constraint layer - and
# dropping the minimum latency, the obvious fix, would have changed nothing.
#
# WHAT THAT DOES NOT ESTABLISH, and an earlier revision of this header claimed
# it did: WHICH post-constraint term held the job. From the source,
# isReadyToBeExecutedLocked() evaluates the constraints and then five further
# terms in order - jobReady (job.isReady() is itself more than the constraint
# columns), jobExists/userStarted/!backingUp, `checkIfRestricted(job) != null`,
# jobPending||jobActive, and isComponentUsable(job) - and a job that passes all
# of them still waits on JobConcurrencyManager for a slot. A JobRestriction is
# one of those, not the only one, and the OLAF timing correlation is a
# correlation. Naming it as the located mechanism would be the fifth causal
# claim in this investigation stated ahead of its evidence.
#
# So the open question is now narrow and the dump answers it directly: the
# per-job `Ready: <bool> (job=... !restricted=... !pending=... !active=... )`
# line decomposes the terms, and `Restricted due to:` names a restriction when
# there is one. This revision captures both; the first did not.
#
# The original fork, kept for the record:
# Two hypotheses remained after force-batching was refuted from AOSP source
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
PROBE_JOB=1145459269          # the observation-only probe, for comparison
NS=dfr-early-root                            # DfrEarlyRoot's dispatching path
PROBE_NS=dfr-early-boot-probe                # EarlyBootProbePolicy.EXPECTED_NAMESPACE
DURATION=${1:-600}
INTERVAL=${2:-5}
OUT=/sdcard/Download/dfr_job_probe_$(date +%Y%m%d_%H%M%S).txt

# Absolute paths and an explicit PATH. The second run of the first revision of
# this script produced ZERO samples and died with `dumpsys: not found`: invoked
# through `su -c`, the environment it inherits need not carry /system/bin. An
# instrument that silently finds no binary is worse than no instrument, so the
# binaries are named outright and their absence is reported.
PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
export PATH
DUMPSYS=/system/bin/dumpsys
CMD=/system/bin/cmd
for b in "$DUMPSYS" "$CMD"; do
    [ -x "$b" ] || { echo "FATAL: $b missing or not executable"; exit 1; }
done

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
# Each record reports its own read status. An absent record and a record this
# shell was not allowed to read are two different facts and must not print the
# same way (AGENTS.md 3.7); `rish` could not read some of these on 2026-10-13,
# and a reader that swallows that difference invites the wrong conclusion.
show() {
    say "--- $1 ---"
    cat "$2" >> "$OUT" 2>&1
    say "[read exit_status=$? path=$2]"
}
show "arm record (may be unreadable without root)" /data/system/dfreroot-early-root-arm
show "cycle record" /data/system/dfreroot-early-root-cycle
show "trace" /data/system/dfreroot-early-root-trace
say ""
say "now_wallclock_ms=$(date +%s%3N)"
say ""

END=$(( $(cut -d. -f1 /proc/uptime) + DURATION ))
N=0
while [ "$(cut -d. -f1 /proc/uptime)" -lt "$END" ]; do
    N=$((N + 1))
    say "########## sample $N  uptime_s=$(cut -d' ' -f1 /proc/uptime)  $(date -u +%H:%M:%S) ##########"
    DUMP=$("$DUMPSYS" jobscheduler 2>&1)
    say "[dumpsys exit_status=$?]"
    # Each job carries its OWN namespace. The namespace is part of a
    # JobScheduler job's identity, so passing the dispatching job's namespace
    # for the probe's id asks about a job that does not exist - it would have
    # recorded a confident answer about nothing. EarlyBootProbePolicy's
    # EXPECTED_NAMESPACE is `dfr-early-boot-probe`; the dispatching path's is
    # `dfr-early-root`.
    for SPEC in "$JOB $NS" "$PROBE_JOB $PROBE_NS"; do
        # shellcheck disable=SC2086
        set -- $SPEC
        J=$1
        JNS=$2
        say "--- job $J (ns=$JNS): the whole per-job block ---"
        # The WHOLE block, delimited at its own boundaries. Two defects, in
        # opposite directions, both of which could put another job's answer
        # under this job's heading:
        #
        #   - the first revision grepped the block for a list of keywords and
        #     dropped parts of it - the owner's 2026-10-13 capture says so -
        #     and the lines that decide this question were not in that list;
        #   - `grep -A 80` then reads a FIXED 80 lines, which on a system uid
        #     with many registered jobs runs past this job's block and into the
        #     next one's, while a longer block puts the wanted line beyond the
        #     limit. Either way the attribution is wrong, and a wrong
        #     attribution here selects the wrong scheduling fix.
        #
        # So the block is cut at the next job header instead of at a line count.
        # `job_block` is used for both the raw copy and the narrowed lines, so
        # the two can never disagree about which block they came from.
        # The header shape is NOT a guess, and the previous revision's was
        # wrong in a way that would have captured nothing. From
        # JobSchedulerService's dump: `pw.print("JOB ")`,
        # `job.printUniqueId(pw)`, `pw.print(": ")`. And from
        # JobStatus.printUniqueId: it prints the namespace then `:` when the
        # job HAS a namespace, and `#` only when it does NOT. So:
        #
        #   JOB dfr-early-root:1000/1145459282: ...      <- ours, namespaced
        #   JOB #u0a211/999: ...                         <- a namespace-less job
        #
        # A matcher requiring `#` therefore excludes exactly the two jobs this
        # probe exists to read. The owner ran the previous revision's awk
        # against the real capture (dfr_job_probe_20261013_211631.txt) and it
        # returned ZERO lines. Match any header, start only on the one whose id
        # ends in `/<job>:`, and stop at the next header whatever its shape.
        job_block() { printf '%s\n' "$DUMP" | awk -v id="/$1:" '
            /^[[:space:]]*JOB[[:space:]]/ {
                if (inb) exit
                if (index($0, id)) { inb = 1; print }
                next
            }
            inb { print }
        '; }
        BLOCK=$(job_block "$J")
        if [ -z "$BLOCK" ]; then
            say "[no block for job $J in this dump - not registered, or the header shape changed]"
        else
            echo "$BLOCK" >> "$OUT" 2>&1
        fi
        say "--- job $J: THE deciding lines ---"
        # Why these, from AOSP source. isReadyToBeExecutedLocked() evaluates
        # the constraints and then, in order, FIVE further terms - any one of
        # which returns false with every constraint satisfied:
        #
        #   jobReady  = job.isReady() || evaluateControllerStatesLocked(job)
        #   jobExists / userStarted / !backingUp
        #   checkIfRestricted(job) != null          <- a JobRestriction veto
        #   jobPending || jobActive
        #   isComponentUsable(job)                  <- package+service viable
        #
        # and a job that passes all of them still waits on
        # JobConcurrencyManager for a slot. So "Unsatisfied constraints: empty
        # and not dispatched" does NOT identify the restriction layer by
        # itself - it only says the wait is past the constraints. The dump's
        # `Ready:` line is what decomposes it, term by term, and
        # `Restricted due to:` is what names a restriction when there is one.
        # `cmd jobscheduler get-job-state` prints neither, which is why the
        # earlier "PERSISTED READY" reading narrowed the question without
        # closing it.
        echo "$BLOCK" | grep -E 'Restricted due to:|^ *Ready: ' >> "$OUT" 2>&1
        say "--- job $J: get-job-state (coarser, kept for continuity) ---"
        "$CMD" jobscheduler get-job-state -n "$JNS" "$PKG" "$J" >> "$OUT" 2>&1
    done
    # The restriction sources, for the case where `Restricted due to:` names
    # one. AOSP ships exactly one JobRestriction - ThermalStatusRestriction -
    # and at THERMAL_STATUS_MODERATE (2) it restricts a PRIORITY_DEFAULT job
    # outright, while at LIGHT (1) it restricts only MIN and LOW. This job
    # prints `Priority: 300 [DEFAULT]`, so the thermal reading is decisive, not
    # background. Samsung adds its own (`restrictJobsByOlaf` / Freecess), whose
    # state this dump also prints. Capturing these is NOT the same as having
    # established that a restriction is what held the job: that is what the
    # per-job lines above are for.
    say "--- restriction sources ---"
    echo "$DUMP" | grep -iE 'thermal|olaf|freecess|restrict' >> "$OUT" 2>&1
    # Concurrency is one of the alternative mechanisms, not colour: a job that
    # passes every term of isReadyToBeExecutedLocked() still waits here.
    say "--- concurrency: is anything else occupying the slots ---"
    echo "$DUMP" | grep -iE 'Max job counts|Running jobs|mNumRunning|active jobs' >> "$OUT" 2>&1
    say ""
    sleep "$INTERVAL"
done

say "=== finished uptime_s=$(cut -d' ' -f1 /proc/uptime) samples=$N ==="
# The scheduler's whole state, once, at the end: the per-job sections above are
# the answer, this is the context for whichever one it turns out to be.
say ""
say "=== full jobscheduler dump (tail) ==="
"$DUMPSYS" jobscheduler >> "$OUT" 2>&1
echo "$OUT"
