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
grab 10_logcat.txt logcat -d -v time
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

# --- THE ANSWER ----------------------------------------------------------
say ""
say "=== READINESS WAIT (the question this boot answers) ==="
# The wait fields ride the EARLY_ROOT_READINESS_PASS step's detail. A refusal
# carries them too, on EARLY_ROOT_REFUSED - that is the case the owner most
# needs to read, so both are pulled.
grep -aE 'EARLY_ROOT_READINESS_PASS|EARLY_ROOT_REFUSED' "$DIR/40_trace.txt" >> "$OUT" 2>/dev/null \
    || say "(no readiness step in the trace - the dispatch did not get that far)"
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
awk '
function ms(t) { split(t, a, ":"); split(a[3], s, "."); 
                 return (a[1]*3600 + a[2]*60 + s[1]) * 1000 + s[2] }
/DFReroot.*EARLY_ROOT\] DISPATCHED/ && match($0, /elapsed_ms=[0-9]+/) {
    e = substr($0, RSTART + 11, RLENGTH - 11); t0 = ms($2) - e
}
{ line[NR] = $0; stamp[NR] = ms($2) }
END {
    if (t0 == "") { print "  t0 UNKNOWN - no DISPATCHED line with elapsed_ms; budget not computable"; exit }
    printf "  t0 (kernel boot) = %s logcat clock\n", t0
    for (i = 1; i <= NR; i++) {
        L = line[i]
        if (L ~ /boot_progress_start:/)            printf "  %7d  zygote (boot_progress_start)\n", stamp[i] - t0
        if (L ~ /boot_progress_system_run:/)       printf "  %7d  system_server (boot_progress_system_run)\n", stamp[i] - t0
        if (L ~ /boot_progress_ams_ready:/)        printf "  %7d  AMS ready  <-- no app process can start before this\n", stamp[i] - t0
        if (L ~ /am_proc_start:.*networkstack/)    printf "  %7d  network_stack forked\n", stamp[i] - t0
        if (L ~ /am_proc_bound:.*networkstack/)    printf "  %7d  network_stack BOUND  <-- earliest readiness can be true\n", stamp[i] - t0
        if (L ~ /EARLY_ROOT\] DISPATCHED/)         printf "  %7d  DFReroot dispatched\n", stamp[i] - t0
        if (L ~ /wm_boot_animation_done: [0-9]/)          printf "  %7d  ANIMATION ENDED  <-- the deadline that matters\n", stamp[i] - t0
        if (L ~ /EARLY_ROOT_RESULT=SUCCESS/)       printf "  %7d  root complete\n", stamp[i] - t0
    }
}' "$DIR/11_timeline.txt" >> "$OUT" 2>> "$DIR/_stderr.txt"

say ""
say "=== NATIVE CHAIN (per-mark deltas, ms) ==="
# The reporter strings DO reach logcat - this is how the 3487 ms LKM write and
# the 2050 ms trigger loop were found, after this record wrongly said they did
# not. Deltas, not absolutes: the absolutes hide where the time goes.
grep -a 'DirtyFrag' "$DIR/10_logcat.txt" | awk '
function ms(t) { split(t, a, ":"); split(a[3], s, ".");
                 return (a[1]*3600 + a[2]*60 + s[1]) * 1000 + s[2] }
{ m = ms($2); if (p == "") { p = m; base = m } d = m - p; p = m
  msg = ""; for (i = 7; i <= NF; i++) msg = msg " " $i
  if (d >= 50 || msg ~ /patch|trigger|MARKER|BOOTSTRAP|PASS|ENTER/)
      printf "  %7d %+6d %s\n", m - base, d, substr(msg, 1, 76) }
' >> "$OUT" 2>> "$DIR/_stderr.txt"

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
