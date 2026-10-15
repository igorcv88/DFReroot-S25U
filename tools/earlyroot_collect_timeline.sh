#!/system/bin/sh
# Collect ONE early-root boot's TIMELINE and pack it into a single archive.
#
#   su -c 'sh /sdcard/Download/earlyroot_collect_timeline.sh'
#
# Companion to tools/earlyroot_collect_pass.sh, not a replacement: that one is
# the per-boot evidence packet (panic records, trace, post-root state, the 3.6.2
# boot-health baseline). This one answers the single question the readiness
# trigger was built to answer, and it exists because of two practical failures:
#
#  - the full logcat of boot cea5208c was 33 MB, which the owner could not
#    upload. So the big file is GZIPPED and a small filtered TIMELINE is written
#    beside it, and everything leaves as ONE tar.gz;
#  - nothing printed the numbers. The whole budget of that boot had to be
#    recovered afterwards by differencing logcat timestamps by hand. So this
#    script PRINTS the answer to the terminal as well as filing it.
#
# It reads only. It arms nothing and clears nothing.
#
# THE QUESTION IT ANSWERS: at what elapsed instant do the four readiness
# components actually flip? Everything else here is corroboration for that one
# number, because it is the structural floor the dispatch has been guessing at.

set -u
PATH=/system/bin:/system/xbin:/vendor/bin
export PATH

TS=$(date +%Y%m%d_%H%M%S)
DIR=/sdcard/Download/dfr_timeline_$TS
OUT=$DIR/00_answer.txt
mkdir -p "$DIR" || { echo "FATAL cannot create $DIR"; exit 1; }

# Every binary this script needs, checked up front. A collection that silently
# skipped a block is indistinguishable from a block that was empty.
for b in logcat dumpsys getprop tar gzip awk grep sed cat; do
    command -v "$b" >/dev/null 2>&1 || echo "FATAL missing binary: $b" >> "$OUT"
done

say() { echo "$@" >> "$OUT"; }
# stderr is captured and the exit status recorded, never discarded.
grab() {
    _f=$1; shift
    "$@" > "$DIR/$_f" 2>> "$DIR/_stderr.txt"
    echo "[$_f exit_status=$?] $*" >> "$OUT"
}

say "=== DFReroot early-root timeline ==="
say "collected_wallclock=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "collected_uptime_s=$(awk '{print $1}' /proc/uptime 2>/dev/null)"
say "uid=$(id -u 2>/dev/null)"
say "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
say "version_name=$(getprop ro.build.version.incremental 2>/dev/null)"
say ""

# --- the raw captures ----------------------------------------------------
# logcat first and in full: it is the only source for am_proc_bound, which is
# the moment the hop's target gets its IApplicationThread, and the logcat
# buffer is the thing that ages out while everything else persists.
#
# `-b all` IS LOAD-BEARING, and leaving it off is how the first version of this
# script was wrong. Every marker the budget is computed from -
# `boot_progress_*`, `am_proc_start`, `am_proc_bound`, `wm_boot_animation_done`
# - is an EVENT-LOG tag, and logcat's default buffer set
# (main,system,crash,kernel) does not include `events`. The capture this
# script's extractors were validated against carries
# `--------- beginning of events`, so it was taken with a different command
# than the one shipped: the offline validation passed while the on-device run
# would have printed a budget with no milestones in it. Codex caught it on
# PR #75. Validating against a real log is not the same as validating against
# a log YOUR OWN command produces.
# `-v threadtime` is as load-bearing as `-b all`, for the same reason and
# found the same way - on the first real run, by the script failing.
#
# The extractors were built and validated against a threadtime capture, where
# an event-log line reads `I boot_progress_ams_ready: 15879`. Shipping
# `-v time` produces `I/boot_progress_ams_ready( 2988): 15879` instead: the
# tag is followed by `/` and `(` rather than a space and `:`, and the pid
# moves from $3 into the tag field. Every tag-anchored pattern in the filter
# below missed, so boot 89e00f66 came back with the whole budget declared
# NOT COMPUTABLE while the milestones sat in the capture.
#
# Third time in this family: a fixture written from memory, then a buffer set
# the shipped command did not request, now a format it did not produce. The
# constant is validating against an input this script did not generate, so the
# filter is now format-agnostic as well - belt and braces, because the next
# variation will not be one that was predicted either.
grab 10_logcat.txt logcat -d -b all -v threadtime
# The boot timeline, from /proc rather than logcat. This is where the budget
# comes from now, and it is the fix for the root cause of every extraction
# defect this script has had: a ring buffer that rolls, a buffer set the
# command did not request, a logcat format it did not produce, a date field
# that moves. None of those exist here. The file is a kernel node, it is
# current-boot, it does not age out within the boot, and its `ktime` column is
# the SAME clock as the trace's elapsed_ms - so no conversion is needed at all.
#
# Found on 2026-10-15 while reading /system/bin/bootchecker for an unrelated
# reason. It had been sitting there through three rounds of increasingly
# careful logcat date arithmetic.
grab 12_enhanced_boot_stat.txt cat /proc/enhanced_boot_stat
grab 13_boot_stat.txt cat /proc/boot_stat
grab 20_jobscheduler.txt dumpsys jobscheduler
grab 30_thermalservice.txt dumpsys thermalservice

# The app's own records. Root-owned, so this script needs su.
for p in trace arm cycle journal incident; do
    cat "/data/system/dfreroot-early-root-$p" > "$DIR/40_$p.txt" 2>> "$DIR/_stderr.txt"
    echo "[40_$p.txt exit_status=$?]" >> "$OUT"
done
cat /data/system/dfreroot-post-root > "$DIR/41_post_root.txt" 2>> "$DIR/_stderr.txt"
echo "[41_post_root.txt exit_status=$?]" >> "$OUT"

# --- the filtered timeline ----------------------------------------------
# Only the lines the budget is computed from. Kept as its own small file so the
# archive is readable without unpacking 33 MB.
# Tag names only, with NO punctuation anchor: `boot_progress_ams_ready:` and
# `boot_progress_ams_ready(` are the same event in two logcat formats, and
# requiring either one is how the previous version silently dropped all of
# them.
grep -aE 'boot_progress_[a-z_]+|wm_boot_animation_done|sf_stop_bootanim|am_proc_start|am_proc_bound|Process [0-9]+ created for com\.android\.networkstack|NetworkStackClient|finishBooting|DFReroot|DirtyFrag' \
    "$DIR/10_logcat.txt" > "$DIR/11_timeline.txt" 2>> "$DIR/_stderr.txt"
echo "[11_timeline.txt exit_status=$? lines=$(wc -l < "$DIR/11_timeline.txt" 2>/dev/null)]" >> "$OUT"

# The capture has to PROVE it holds the events buffer rather than be assumed
# to. A missing buffer and a boot that never logged a milestone look identical
# in the output otherwise, and the first is a defect in this script while the
# second is a fact about the device (AGENTS.md 3.7).
# The rescue counters, every run. sys.rescue_boot_count counts boots in quick
# succession, which IS this project's test cycle: arm, reboot, collect, reboot.
# It read 2 on 2026-10-15 with rescue_level 0 and no rescueparty log ever
# written - no past escalation, but the counter is not idle, and nobody was
# watching it. /system/bin/bootchecker's own escalation path contains
# --prompt_and_wipe_app_data, so this is not a cosmetic number.
say ""
say "=== rescue / boot-health counters ==="
for k in sys.rescue_boot_count sys.prev.rescue_boot_count persist.sys.rescue_level \
         dev.boot_count crashrecovery.rescue_boot_count \
         persist.device_config.configuration.disable_rescue_party_factory_reset; do
    say "$k=$(getprop "$k" 2>/dev/null)"
done

say ""
say "=== events buffer present? (the budget is unreadable without it) ==="
EVB=$(grep -ac 'beginning of events' "$DIR/10_logcat.txt" 2>/dev/null)
MARK=$(grep -ac 'boot_progress_ams_ready:' "$DIR/11_timeline.txt" 2>/dev/null)
BND=$(grep -ac 'am_proc_bound:.*networkstack' "$DIR/11_timeline.txt" 2>/dev/null)
say "events_buffer_header=$EVB boot_progress_ams_ready=$MARK am_proc_bound_networkstack=$BND"
# EVB and MARK answer DIFFERENT questions, and keying the verdict on MARK alone
# was wrong. logcat's ring buffer rolls: a collection taken late on a busy
# device can lose a 13 s milestone while still carrying the whole `events`
# buffer. Blaming the capture command there sends the owner to re-run with a
# flag that was already set, when the real instruction is "collect sooner".
# Buffer absent is a defect in THIS SCRIPT; milestone absent is a fact about
# WHEN the collection was taken (AGENTS.md 3.7).
if [ "${EVB:-0}" -eq 0 ]; then
    say "FATAL no 'beginning of events' header: this capture omitted the event"
    say "      buffer entirely. Re-run with: logcat -d -b all"
elif [ "${MARK:-0}" -eq 0 ]; then
    say "WARNING the events buffer IS present but boot_progress_ams_ready is not"
    say "        in it. The early boot lines have aged out of the ring buffer -"
    say "        collect SOONER after the boot. This is not a missing flag and"
    say "        not a slow boot."
fi

# --- THE ANSWER ----------------------------------------------------------
say ""
say "=== READINESS WAIT (the question this boot answers) ==="
# The wait fields ride the EARLY_ROOT_READINESS_PASS step's detail. A refusal
# carries them too, on EARLY_ROOT_REFUSED - that is the case the owner most
# needs to read, so both are pulled.
# Matching the STEP NAMES is not enough, and the first version of this block
# got it wrong. The dispatch can refuse before the readiness sweep ever runs -
# the arm-binding refusal and the durable-policy refusal both do - and those
# write EARLY_ROOT_REFUSED with no `wait=` detail at all. A grep on the step
# name then succeeds, the fallback message never prints, and the section shows
# a refusal with neither a measurement nor a statement that none was taken.
# That is precisely the UNKNOWN a reader has to guess about (AGENTS.md 3.7).
# So the test is for the FIELD, and its absence is reported as its own fact.
grep -aE 'EARLY_ROOT_READINESS_PASS|EARLY_ROOT_REFUSED' "$DIR/40_trace.txt" >> "$OUT" 2>/dev/null
if grep -aq 'wait=' "$DIR/40_trace.txt" 2>/dev/null; then
    :
elif [ -s "$DIR/40_trace.txt" ]; then
    say ""
    say "NO READINESS MEASUREMENT IN THIS BOOT. The trace exists but carries no"
    say "wait= field, so the dispatch refused BEFORE the readiness sweep ran"
    say "(arm binding, or the durable policy). The refusal line above says which."
    say "This is not an expired wait and not a slow boot: nothing was measured."
else
    say ""
    say "NO TRACE. Either the trigger never fired in this boot, or it fired and"
    say "died before its first durable write. Those are different facts and this"
    say "collection cannot tell them apart - check the arm record below."
fi
say ""
say "how to read wait= :"
say "  WAIT_PROCEED            readiness arrived; ready_at_ms IS the structural floor"
say "  WAIT_EXPIRED            readiness never arrived in 17 s - the only one about the BOOT"
say "  WAIT_CLOCK_UNAVAILABLE  monotonicNow() threw; says NOTHING about readiness"
say "  WAIT_INTERRUPTED        something interrupted the thread; says NOTHING about readiness"
say "  WAIT_NOT_PERMITTED      a DEFECT in DFReroot's threading, not the boot"
say ""

say "=== THE BUDGET (ktime ms, from /proc/enhanced_boot_stat) ==="
# No logcat, no clock conversion, no date. The `ktime` column of
# /proc/enhanced_boot_stat is the same clock the trace's elapsed_ms uses, so
# these numbers and the trace's are directly comparable with no arithmetic.
#
# Field layout: a milestone line is `!@Boot_EBS_x: <name>  <time> <ktime> <delta>`
# so ktime is $(NF-1). A `Took Nms by '...'` line has only <time> <ktime>, which
# is why only !@Boot_EBS_ lines are parsed - taking $NF blindly would read the
# delta on one shape and the ktime on the other.
# The ENTRY instant comes from the TRACE, always, and never from logcat: ENTRY
# and DISPATCH are different boundaries (~165 ms apart), and the logcat line
# ages out while /data/system does not.
#
# WHICH entry step depends on which trigger claimed the run. The job writes
# EARLY_ROOT_JOB_ENTERED; LOCKED_BOOT_COMPLETED writes
# EARLY_ROOT_TRIGGER_ENTERED (AGENTS.md 3.11 keeps the names separate so a
# reader can tell which trigger got there). Hardcoding the job's step leaves
# this empty on any boot the broadcast won.
#
# This block was deleted once, by a line-range replacement that moved the
# budget to /proc, and the deletion was invisible because the awk below was
# tested with `-v tracedisp=17847` fed in by hand - an input this script does
# not produce. Codex caught it on PR #78. Test the SHELL, not the awk.
TRACE_CLAIM_TRIGGER=$(awk -F'\t' '$1 == "EARLY_ROOT_CLAIMED" {
    if (match($5, /trigger=[^ ]+/)) print substr($5, RSTART + 8, RLENGTH - 8); exit }' \
    "$DIR/40_trace.txt" 2>/dev/null)
case "${TRACE_CLAIM_TRIGGER:-}" in
    job)  TRACE_ENTRY_STEP=EARLY_ROOT_JOB_ENTERED ;;
    "")   TRACE_ENTRY_STEP= ;;
    *)    TRACE_ENTRY_STEP=EARLY_ROOT_TRIGGER_ENTERED ;;
esac
if [ -n "${TRACE_ENTRY_STEP:-}" ]; then
    TRACE_DISPATCH=$(awk -F'\t' -v step="$TRACE_ENTRY_STEP" \
        '$1 == step { print $3; exit }' "$DIR/40_trace.txt" 2>/dev/null)
else
    # No claim recorded, so no trigger owns the run. Take the earliest entry
    # step present rather than guessing a trigger, and say so.
    TRACE_DISPATCH=$(awk -F'\t' \
        '$1 == "EARLY_ROOT_JOB_ENTERED" || $1 == "EARLY_ROOT_TRIGGER_ENTERED" \
         { print $3; exit }' "$DIR/40_trace.txt" 2>/dev/null)
fi
say "entry step=${TRACE_ENTRY_STEP:-<no claim recorded>} claimed_trigger=${TRACE_CLAIM_TRIGGER:-<none>} entry_elapsed_ms=${TRACE_DISPATCH:-<none>}"
awk -v tracedisp="${TRACE_DISPATCH:-}" '
/^!@Boot_EBS_/ {
    k = $(NF-1) + 0
    if (/starting service .zygote/)                  m["zygote"] = k
    if (/BOOT_PROGRESS_SYSTEM_RUN/)                  m["system_server"] = k
    if (/boot_progress_pms_ready/)                   m["PMS ready"] = k
    if (/PHASE_SYSTEM_SERVICES_READY/)               m["phase SYSTEM_SERVICES_READY"] = k
    if (/boot_progress_ams_ready/)                 { m["AMS ready  <-- no app process starts before this"] = k; ams = k }
    if (/PHASE_THIRD_PARTY_APPS_CAN_START/)          m["phase THIRD_PARTY_APPS_CAN_START"] = k
    if (/wm_boot_animation_done/)                  { m["ANIMATION ENDED  <-- the deadline that matters"] = k; anim = k }
    if (/bootcomplete/)                            { m["firmware bootcomplete (bootchecker)"] = k; bc = k }
}
END {
    n = 0; for (kk in m) { n++; key[n] = kk }
    if (n == 0) {
        print "  NOT COMPUTABLE: /proc/enhanced_boot_stat held no !@Boot_EBS_ lines."
        print "  That is a missing or unreadable kernel node, not a slow boot and"
        print "  not a logcat problem - check 12_enhanced_boot_stat.txt."
        exit
    }
    for (i = 1; i <= n; i++) for (j = i+1; j <= n; j++)
        if (m[key[j]] < m[key[i]]) { t = key[i]; key[i] = key[j]; key[j] = t }
    for (i = 1; i <= n; i++) printf "  %7d  %s\n", m[key[i]], key[i]

    # The animation window, which is the quantity the whole project races. It
    # measured 4433 / 4474 / 4474 ms across three boots - a 41 ms spread - while
    # the absolute instants moved by 2.6 s. So the budget is stated RELATIVE to
    # AMS ready; stating it in absolute ms made a stable structure look noisy.
    if (ams > 0 && anim > 0) {
        printf "\n  animation window (ANIMATION ENDED - AMS ready) = %d ms\n", anim - ams
        print  "  reference: 4433 / 4474 / 4474 ms over three boots (41 ms spread)."
    }
    if (bc > 0 && anim > 0)
        printf "  firmware bootcomplete follows the animation by %d ms (ref 289)\n", bc - anim
    if (tracedisp == "") {
        if (ams > 0) print "\n  entry - AMS ready: NOT COMPUTABLE, no entry step in the trace."
    } else if (ams > 0) {
        e = tracedisp + 0
        printf "\n  entry - AMS ready = %d ms  <-- what governs our start, and it\n", e - ams
        print  "  is not minimum_latency_ms. Reference: 2042 ms on a 15 s floor,"
        print  "  1968 ms on a 10 s floor. Both floors sit BELOW AMS ready."
        if (anim > 0) {
            printf "  animation left when we entered = %d ms\n", anim - e
            print  "  the chain entry->root measured 8971 and 11395 ms, so that is"
            print  "  the deficit this path has to close."
        }
        printf "  (entry from the trace, elapsed %d; see the entry step line above)\n", e
    }
}
' "$DIR/12_enhanced_boot_stat.txt" >> "$OUT" 2>> "$DIR/_stderr.txt"

say ""
say "=== NATIVE CHAIN (per-mark deltas, ms) ==="
# The reporter strings DO reach logcat - this is how the 3487 ms LKM write and
# the 2050 ms trigger loop were found, after the evidence record wrongly said
# they did not. Deltas, not absolutes: the absolutes hide where the time goes.
#
# MARKS ARE ATTRIBUTED TO A RUN, and taking every DirtyFrag line in the buffer
# was wrong. Per AGENTS.md 3.11's R1 rule a pre-transaction failure does not
# spend the boot, so Auto Root may run LATER IN THE SAME BOOT - and the manual
# button can too. An unattributed grep then either shows the wrong run, or
# concatenates two and reports the minutes between them as a native delta: a
# fabricated number in the one section that exists to produce real ones.
#
# So runs are split on the native chains own first report
# ([DFR][PREFLIGHT] NETLINK_XFRM), each gets its own base, the count is stated,
# and each is marked for whether it falls inside the early dispatch window.
awk '
function tod(t) { split(t, a, ":"); split(a[3], s, ".")
                  return (a[1]*3600 + a[2]*60 + s[1]) * 1000 + s[2] }
# Same conversion as the budget, for the reason this section exists: it is
# where 3487 ms of LKM write and 2050 ms of trigger loop were found, so a mark
# quietly dropped is a delay quietly hidden. The previous version skipped every
# mark whose date differed from its run start, so a run crossing midnight
# printed as complete while omitting everything after 00:00 - the worst
# possible failure in the one section meant to show where time goes.
function dayidx(ds) { split(ds, q, "-")
    c[1]=0;   c[2]=31;  c[3]=60;  c[4]=91;  c[5]=121; c[6]=152
    c[7]=182; c[8]=213; c[9]=244; c[10]=274; c[11]=305; c[12]=335
    return c[q[1]+0] + (q[2]+0) }
{ d[NR] = $1; v[NR] = tod($2); L[NR] = $0
  msg = ""; for (i = 7; i <= NF; i++) msg = msg " " $i
  M[NR] = msg
  if ($0 ~ /DirtyFrag/) { isdf[NR] = 1; ndf++ }
  if ($0 ~ /EARLY_ROOT\] DISPATCHED/) disp = NR
  if ($0 ~ /EARLY_ROOT_RESULT/) res = NR }
END {
    if (ndf == 0) { print "  (no DirtyFrag marks in this buffer - the native chain never reported)"; exit }
    runs = 0
    for (i = 1; i <= NR; i++)
        if (isdf[i] && M[i] ~ /PREFLIGHT\] NETLINK_XFRM/) { runs++; rstart[runs] = i }
    if (runs == 0) {
        print "  MARKS PRESENT BUT UNATTRIBUTABLE: no [DFR][PREFLIGHT] NETLINK_XFRM"
        print "  line, so where a run begins is unknown and differencing across"
        print "  them would invent deltas. Raw marks are in 11_timeline.txt."
        exit
    }
    printf "  native runs found in this buffer: %d\n", runs
    if (runs > 1)
        print "  MORE THAN ONE RUN. Auto Root or the manual button also ran in this\n  boot. Each is printed separately; deltas are never taken across runs."
    for (r = 1; r <= runs; r++) {
        lo = rstart[r]; hi = (r < runs ? rstart[r+1] - 1 : NR)
        inwin = (disp != "" && lo >= disp && (res == "" || lo <= res)) ? "INSIDE the early dispatch window" : "OUTSIDE the early dispatch window (not the early attempt)"
        printf "\n  --- run %d of %d: %s ---\n", r, runs, inwin
        base = ""; p = ""; li = dayidx(d[lo]); dropped = 0
        for (i = lo; i <= hi; i++) {
            if (!isdf[i]) continue
            gap = dayidx(d[i]) - li
            # A real midnight rollover is NORMALISED, not discarded. Any other
            # date movement is a clock correction: the marks after it cannot be
            # placed on this run, so the run is declared uncomputable rather
            # than printed as if it had ended there.
            if (gap == 0) off = 0
            else if (gap == 1 && v[i] < v[lo]) off = 86400000
            else { dropped++; continue }
            m = v[i] + off
            if (base == "") { base = m; p = m }
            delta = m - p; p = m
            if (delta >= 50 || M[i] ~ /patch|trigger|MARKER|BOOTSTRAP|PASS|ENTER/)
                printf "  %7d %+6d %s\n", m - base, delta, substr(M[i], 1, 74)
        }
        if (dropped > 0)
            printf "  RUN INCOMPLETE: %d later marks could not be placed (the wall\n  clock moved mid-run). The deltas above end where that happened; do\n  not read this run as finished. Raw marks: 11_timeline.txt\n", dropped
    }
}' "$DIR/11_timeline.txt" >> "$OUT" 2>> "$DIR/_stderr.txt"

say ""
say "=== thermal at collection ==="
grep -aE 'Thermal Status|mName=(SKIN|AP)' "$DIR/30_thermalservice.txt" >> "$OUT" 2>/dev/null

# --- one archive ---------------------------------------------------------
# The whole point: the logcat is gzipped inside the tarball, so a 33 MB capture
# leaves as a couple of MB and the owner can actually upload it.
gzip -f "$DIR/10_logcat.txt" 2>> "$DIR/_stderr.txt"
ARCHIVE=/sdcard/Download/dfr_timeline_$TS.tar.gz
tar -czf "$ARCHIVE" -C /sdcard/Download "dfr_timeline_$TS" 2>> "$DIR/_stderr.txt"
RC=$?

echo ""
cat "$OUT"
echo ""
if [ $RC -eq 0 ]; then
    echo "=== SEND THIS ONE FILE ==="
    ls -la "$ARCHIVE"
else
    echo "=== tar FAILED (rc=$RC); send the directory instead ==="
    echo "$DIR"
fi
