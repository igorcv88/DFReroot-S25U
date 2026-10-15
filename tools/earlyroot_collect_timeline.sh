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

say "=== THE BUDGET (elapsed ms, from logcat) ==="
# Anchored on the kernel-boot t0 that the DFReroot trace and logcat share: the
# DISPATCHED line carries both a logcat timestamp and its own elapsed_ms, so t0
# is derived rather than assumed.
#
# THE DATE FIELD IS PART OF THE TIMESTAMP, and ignoring it was a real bug, not
# a theoretical one. Two things move the date inside one boot's buffer:
#
#  - a boot that crosses MIDNIGHT. Time-of-day alone then goes backwards and
#    t0 comes out negative, putting pre-midnight events ~24 h after boot;
#  - the CLOCK BEING SET during boot, which happens in every boot. The
#    cea5208c capture carries 3647 lines dated 02-02 (pre-NTP) followed by
#    221580 dated 10-14. All 86 budget markers were in the 10-14 block there,
#    so this did not corrupt that budget - but nothing made that true, and a
#    marker landing on the far side of the clock set would have been silently
#    off by eight months.
#
# So dates are tracked in order of appearance FROM THE ANCHOR onward, each new
# one worth one day, and a line whose date is not in that set is SKIPPED and
# COUNTED rather than converted against the wrong origin. Counting matters:
# skipping silently would hide a marker that fell before the clock set.
# The dispatch instant comes from the TRACE, not from logcat, because the
# logcat line ages out while /data/system does not - boot 89e00f66 lost it at
# 71 s of uptime. It is the one number this collection exists to compare
# against AMS ready, so it must not depend on the buffer that rolls.
TRACE_DISPATCH=$(awk -F'\t' '$1 == "EARLY_ROOT_JOB_ENTERED" { print $3; exit }' \
    "$DIR/40_trace.txt" 2>/dev/null)
awk -v tracedisp="${TRACE_DISPATCH:-}" '
function tod(t) { split(t, a, ":"); split(a[3], s, ".")
                  return (a[1]*3600 + a[2]*60 + s[1]) * 1000 + s[2] }
function dayidx(ds) { split(ds, q, "-")
    c[1]=0;   c[2]=31;  c[3]=60;  c[4]=91;  c[5]=121; c[6]=152
    c[7]=182; c[8]=213; c[9]=244; c[10]=274; c[11]=305; c[12]=335
    return c[q[1]+0] + (q[2]+0) }
# The platform milestones REPORT THEIR OWN ELAPSED MS as the message body, in
# both logcat formats: `boot_progress_ams_ready: 15879` and
# `boot_progress_ams_ready( 2988): 15879` both end in 15879. Reading that value
# is exact, needs no clock at all, and is therefore immune to the whole class
# of date problems - midnight, the pre-NTP clock set, a correction mid-boot.
# This was sitting in the log the entire time and I was converting timestamps
# instead; boot 89e00f66 is where reading the raw lines showed it.
#
# Only am_proc_start / am_proc_bound do not self-report (their message is the
# process tuple), so they alone still need a clock, and t0 comes from a
# self-reporting milestone on a line of the same capture: t0 = clock - value.
/boot_progress_start|boot_progress_system_run|boot_progress_pms_ready|boot_progress_ams_ready|boot_progress_enable_screen|wm_boot_animation_done/ {
    if ($NF ~ /^[0-9]+$/) {
        val = $NF + 0
        if (/boot_progress_start/)          self["zygote"] = val
        if (/boot_progress_system_run/)     self["system_server"] = val
        if (/boot_progress_pms_ready/)      self["PMS ready"] = val
        if (/boot_progress_ams_ready/)    { self["AMS ready  <-- no app process starts before this"] = val
                                            t0 = tod($2) - val; t0d = dayidx($1) }
        if (/boot_progress_enable_screen/)  self["screen enabled"] = val
        if (/wm_boot_animation_done/)       self["ANIMATION ENDED  <-- the deadline that matters"] = val
    }
}
{ d[NR] = $1; v[NR] = tod($2); L[NR] = $0 }
/EARLY_ROOT\] DISPATCHED/ && match($0, /elapsed_ms=[0-9]+/) {
    self["DFReroot dispatched"] = substr($0, RSTART + 11, RLENGTH - 11) + 0 }
/EARLY_ROOT_RESULT=SUCCESS/ { resline = NR }
END {
    n = 0; for (k in self) n++
    if (n == 0) {
        print "  NOT COMPUTABLE: no platform milestone in this capture. Either the"
        print "  event buffer was not captured, or the lines aged out of the ring"
        print "  buffer before collection, or the logcat FORMAT changed and the"
        print "  filter missed them. The three are different problems - compare"
        print "  events_buffer_header above against a grep of 10_logcat.txt."
        exit
    }
    # Sort by value, so the order is the boot order whatever was found.
    for (k in self) { nk++; key[nk] = k }
    for (i = 1; i <= nk; i++) for (j = i+1; j <= nk; j++)
        if (self[key[j]] < self[key[i]]) { tmp = key[i]; key[i] = key[j]; key[j] = tmp }
    # am_proc_* need the clock, and only when a self-reporting anchor gave t0.
    if (t0 != "") {
        for (i = 1; i <= NR; i++) {
            if (L[i] !~ /networkstack\.process/) continue
            gap = dayidx(d[i]) - t0d
            if (gap == 0) off = 0
            else if (gap == 1 && v[i] < t0) off = 86400000
            else { unplaceable++; continue }
            if (L[i] ~ /am_proc_start/ && !seenstart++) ap["network_stack forked"] = v[i] + off - t0
            if (L[i] ~ /am_proc_bound/ && !seenbound++) ap["network_stack BOUND  <-- earliest readiness can be true"] = v[i] + off - t0
        }
        for (k in ap) { nk++; key[nk] = k; self[k] = ap[k] }
        for (i = 1; i <= nk; i++) for (j = i+1; j <= nk; j++)
            if (self[key[j]] < self[key[i]]) { tmp = key[i]; key[i] = key[j]; key[j] = tmp }
    }
    for (i = 1; i <= nk; i++) printf "  %7d  %s\n", self[key[i]], key[i]
    if (t0 == "")
        print "  (am_proc_* omitted: no self-reporting milestone to anchor a clock on)"
    if (unplaceable > 0)
        printf "  (%d am_proc_* lines unplaceable: the wall clock moved)\n", unplaceable
    # The two numbers the whole collection exists for, stated rather than left
    # to the reader to subtract.
    disp = 0; for (k in self) if (k ~ /dispatched/) disp = self[k]
    amsr = 0; for (k in self) if (k ~ /AMS ready/) amsr = self[k]
    src = "logcat"
    if (disp == 0 && tracedisp != "") { disp = tracedisp + 0; src = "trace" }
    if (disp > 0 && amsr > 0) {
        printf "\n  job entry - AMS ready = %d ms  <-- what actually governs our\n", disp - amsr
        print  "  start, not minimum_latency_ms. Boot cea5208c: 2205 ms on a 15 s"
        print  "  floor. Boot 89e00f66: 1968 ms on a 10 s floor. Both floors sit"
        print  "  BELOW AMS ready, so neither one binds."
        printf "  (job entry read from %s, elapsed %d)\n", src, disp
    }
    if (anim > 0) print "  (root completion is in 40_trace.txt: POST_ROOT_COMPLETE)"
}
' "$DIR/11_timeline.txt" >> "$OUT" 2>> "$DIR/_stderr.txt"

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
