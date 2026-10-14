#!/bin/sh
# The per-job block extractor in tools/earlyroot_job_probe.sh, on the host.
#
# Why this test exists: that extractor has now been wrong twice, in opposite
# directions, and both times the error would have put another job's answer
# under our job's heading - or captured nothing at all - in the one physical
# measurement the whole JobScheduler investigation is waiting on.
#
#   1. `grep -A 80` read a FIXED line count, so it ran past the target's block
#      into the next job's (emitting that job's `Restricted due to:` under this
#      job's heading) and truncated a block longer than the limit.
#   2. The awk that replaced it required `JOB #` in the header. From
#      JobStatus.printUniqueId, `#` is printed ONLY when a job has no
#      namespace; DFReroot's two jobs are namespaced, so their headers read
#      `JOB dfr-early-root:1000/1145459282:` with no `#`. That matcher
#      excluded exactly the two jobs the probe exists to read, and the owner
#      confirmed zero lines against the real capture.
#
# The second defect passed a test built from a fixture invented from memory.
# So the fixtures below carry BOTH real header shapes, taken from the dump
# code's own output format:
#
#   pw.print("JOB "); job.printUniqueId(pw); pw.print(": ");
#   printUniqueId -> "<namespace>:<uid>/<id>"  when namespaced
#                    "#<uid>/<id>"             when not
#
# It extracts the awk program from the shipped script rather than copying it,
# so a future edit to the script is what this test reads.
set -eu
cd "$(dirname "$0")/../.."

PROBE=tools/earlyroot_job_probe.sh
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The awk program as shipped: the lines between the `awk -v id=` invocation and
# the closing `'; }` of job_block.
sed -n "/job_block() { printf .* | awk -v id=/,/^ *'; }\$/p" "$PROBE" \
    | sed -e '1s/.*awk -v id="\/\$1:" .//' -e "\$d" > "$WORK/block.awk"
[ -s "$WORK/block.awk" ] || {
    echo "FAIL: could not extract the awk program from $PROBE"
    echo "      (job_block's shape changed - update this test deliberately)"
    exit 1
}

cat > "$WORK/dump.txt" <<'EOF'
Registered 201 jobs:
  JOB #u0a211/999: com.other/.Svc
    Required constraints: TIMING_DELAY
    Restricted due to: THERMAL.
    Ready: false (job=false !restricted=false !pending=true !active=true)
  JOB dfr-early-root:1000/1145459282: com.polygraphene.df.reroot/.DfrEarlyRootJobService
    Required constraints: TIMING_DELAY DEADLINE FLEXIBILITY
    Unsatisfied constraints:
    Standby bucket: EXEMPTED
    Priority: 300 [DEFAULT]
    Restricted due to: none.
    Ready: true (job=true !restricted=true !pending=true !active=true)
  JOB dfr-early-boot-probe:1000/1145459269: com.polygraphene.df.reroot/.DfrEarlyBootJobService
    Restricted due to: OLAF.
    Ready: false (job=true !restricted=false !pending=true !active=true)
  JOB #u0a77/55: com.z/.S
    Restricted due to: SOMETHING_ELSE.
EOF

# A target whose block is longer than the 80 lines the old form read.
{
    echo "Registered 2 jobs:"
    echo "  JOB dfr-early-root:1000/1145459282: svc"
    i=1
    while [ "$i" -le 95 ]; do echo "    filler $i"; i=$((i + 1)); done
    echo "    Restricted due to: none."
    echo "    Ready: true (job=true !restricted=true)"
} > "$WORK/long.txt"

FAILED=0
check() { # label expected_count expected_substring file job
    got=$(awk -v id="/$5:" -f "$WORK/block.awk" "$4" | wc -l | tr -d ' ')
    if [ "$got" != "$2" ]; then
        echo "FAIL: $1: expected $2 block lines, got $got"
        FAILED=1
        return
    fi
    if [ -n "$3" ]; then
        dec=$(awk -v id="/$5:" -f "$WORK/block.awk" "$4" \
              | grep -cE 'Restricted due to:' || true)
        if [ "$dec" != "1" ]; then
            echo "FAIL: $1: expected exactly 1 'Restricted due to:' line, got $dec"
            FAILED=1
            return
        fi
        if ! awk -v id="/$5:" -f "$WORK/block.awk" "$4" | grep -q "$3"; then
            echo "FAIL: $1: block does not contain '$3'"
            FAILED=1
            return
        fi
    fi
    echo "ok: $1"
}

# THE regression that shipped: a namespaced header must be found at all.
check "namespaced target is found (the #-requiring matcher found nothing)" \
      7 "Restricted due to: none." "$WORK/dump.txt" 1145459282
# ... and must not absorb the next job's lines, whatever that job's shape.
check "namespaced probe job, own block only" \
      3 "Restricted due to: OLAF." "$WORK/dump.txt" 1145459269
# A namespace-less header still works, since the dump mixes both.
check "namespace-less header still matches" \
      4 "Restricted due to: THERMAL." "$WORK/dump.txt" 999
# A block longer than the old fixed window is not truncated.
check "block longer than 80 lines is complete" \
      98 "Restricted due to: none." "$WORK/long.txt" 1145459282
# An unregistered id yields nothing, so the caller can report it as a named
# condition rather than printing another job's block.
check "unregistered id yields no block" 0 "" "$WORK/dump.txt" 1145459999

# And the bleed, stated as the property that matters: exactly one deciding pair
# per target, across every target in the fixture.
for J in 999 1145459282 1145459269; do
    n=$(awk -v id="/$J:" -f "$WORK/block.awk" "$WORK/dump.txt" \
        | grep -cE '^ *Ready: ' || true)
    if [ "$n" != "1" ]; then
        echo "FAIL: job $J: expected exactly 1 'Ready:' line, got $n"
        FAILED=1
    fi
done
[ "$FAILED" = 0 ] && echo "ok: one 'Ready:' line per target, no bleed"

if [ "$FAILED" != 0 ]; then
    echo "job probe extractor tests FAILED"
    exit 1
fi
echo "job probe extractor: all checks passed"
