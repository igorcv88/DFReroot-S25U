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
grab 10_logcat.txt logcat -d -b all -v time
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
grep -aE 'boot_progress_[a-z_]+:|wm_boot_animation_done|sf_stop_bootanim|am_proc_start:.*networkstack|am_proc_bound:.*networkstack|Process [0-9]+ created for com\.android\.networkstack|NetworkStackClient|finishBooting|boot_progress_ams_state|DFReroot|DirtyFrag' \
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
if [ "${MARK:-0}" -eq 0 ]; then
    say "FATAL the event-log markers are ABSENT. The budget below is NOT a slow"
    say "      boot and NOT a missing milestone - it is this capture missing the"
    say "      events buffer. Re-run with: logcat -d -b all"
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
awk '
function tod(t) { split(t, a, ":"); split(a[3], s, ".")
                  return (a[1]*3600 + a[2]*60 + s[1]) * 1000 + s[2] }
{ d[NR] = $1; v[NR] = tod($2); L[NR] = $0
  if ($0 ~ /boot_progress_ams_ready:/) sawevents = 1
  if (anchor == 0 && $0 ~ /DFReroot.*EARLY_ROOT\] DISPATCHED/ \
      && match($0, /elapsed_ms=[0-9]+/)) {
      anchor = NR; el = substr($0, RSTART + 11, RLENGTH - 11) } }
END {
    # The section refuses on its own, not only via the check further up. The
    # DISPATCHED line lives in the MAIN buffer, so it survives a capture taken
    # without `events` - and the budget would then print two orphan DFReroot
    # lines that look like a complete answer to anyone reading from here.
    if (!sawevents) {
        print "  NOT COMPUTABLE: this capture has no event-log milestones."
        print "  Every marker the budget needs (boot_progress_*, am_proc_*,"
        print "  wm_boot_animation_done) is an event-log tag, and the default logcat"
        print "  buffers exclude `events`. Re-run with: logcat -d -b all"
        print "  This is a defect in the CAPTURE, not a slow boot."
        exit
    }
    if (anchor == 0) {
        print "  NOT COMPUTABLE: no DISPATCHED line carrying elapsed_ms, so the"
        print "  logcat clock cannot be tied to the boot clock. Refusing to print"
        print "  a budget against a guessed origin."
        exit
    }
    # Distinct dates from the anchor forward; the anchor date is day 0.
    nd = 0
    for (i = anchor; i <= NR; i++)
        if (!(d[i] in day)) { day[d[i]] = nd * 86400000; nd++ }
    t0 = v[anchor] - el
    skipped = 0
    for (i = 1; i <= NR; i++) {
        if (!(d[i] in day)) { skipped++; continue }
        e = v[i] + day[d[i]] - t0
        if (L[i] ~ /boot_progress_start:/)         printf "  %7d  zygote\n", e
        if (L[i] ~ /boot_progress_system_run:/)    printf "  %7d  system_server\n", e
        if (L[i] ~ /boot_progress_ams_ready:/)     printf "  %7d  AMS ready  <-- no app process starts before this\n", e
        if (L[i] ~ /am_proc_start:.*networkstack/) printf "  %7d  network_stack forked\n", e
        if (L[i] ~ /am_proc_bound:.*networkstack/) printf "  %7d  network_stack BOUND  <-- earliest readiness can be true\n", e
        if (L[i] ~ /EARLY_ROOT\] DISPATCHED/)      printf "  %7d  DFReroot dispatched\n", e
        if (L[i] ~ /wm_boot_animation_done: [0-9]/) printf "  %7d  ANIMATION ENDED  <-- the deadline that matters\n", e
        if (L[i] ~ /EARLY_ROOT_RESULT=SUCCESS/)    printf "  %7d  root complete\n", e
    }
    if (skipped > 0)
        printf "  (%d lines skipped: dated before the clock was set, so they\n   cannot be placed on this boot clock)\n", skipped
}' "$DIR/11_timeline.txt" >> "$OUT" 2>> "$DIR/_stderr.txt"

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
        base = ""; p = ""
        for (i = lo; i <= hi; i++) {
            if (!isdf[i]) continue
            if (d[i] != d[lo]) continue
            m = v[i]; if (base == "") { base = m; p = m }
            delta = m - p; p = m
            if (delta >= 50 || M[i] ~ /patch|trigger|MARKER|BOOTSTRAP|PASS|ENTER/)
                printf "  %7d %+6d %s\n", m - base, delta, substr(M[i], 1, 74)
        }
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
