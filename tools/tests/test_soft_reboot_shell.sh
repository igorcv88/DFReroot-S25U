#!/bin/sh
# The privileged shell the soft-reboot action hands to `su -c`, driven against
# scratch files.
#
# It exists because that one string is the only place in this repository where a
# digest comparison decides whether a privileged binary runs, and it is composed in
# Kotlin - which nothing in this environment can compile - and executed by a shell
# nothing in this environment can reach. What CAN be tested is the shell itself, so
# it is, exactly as DfrSoftRebootReceiver composes it.
#
# The `exec` target is replaced by an echo here: the point is which paths reach the
# exec, never running ksud.
set -eu
cd "$(dirname "$0")/../.."
RECEIVER=app/src/main/java/com/polygraphene/df/reroot/DfrSoftRebootReceiver.kt
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0
fail=0

# The exit status and the shape must match the source, or this tests a fiction.
RC=$(sed -n 's/.*const val RC_DIGEST_CHANGED = \([0-9]*\).*/\1/p' "$RECEIVER")
[ -n "$RC" ] || { echo "FAIL: RC_DIGEST_CHANGED not found in $RECEIVER"; exit 1; }
for fragment in 'sha256sum \"\$p\"' "cut -d' ' -f1" "grep -qx '" 'exec \"\$p\" soft-reboot'; do
    grep -qF "$fragment" "$RECEIVER" || {
        echo "FAIL: $RECEIVER no longer composes [$fragment]"; exit 1; }
done

check() {
    name="$1"; path="$2"; digest="$3"; want_rc="$4"; want_exec="$5"
    set +e
    out=$(sh -c "p='$path'; sha256sum \"\$p\" 2>/dev/null | cut -d' ' -f1 \
| grep -qx '$digest' || exit $RC; echo EXEC_REACHED" 2>/dev/null)
    rc=$?
    set -e
    got_exec=no
    [ "$out" = "EXEC_REACHED" ] && got_exec=yes
    if [ "$rc" = "$want_rc" ] && [ "$got_exec" = "$want_exec" ]; then
        pass=$((pass + 1)); printf '  ok   - %s (rc=%s exec=%s)\n' "$name" "$rc" "$got_exec"
    else
        fail=$((fail + 1))
        printf '  FAIL - %s: rc=%s want %s, exec=%s want %s\n' \
            "$name" "$rc" "$want_rc" "$got_exec" "$want_exec"
    fi
}

echo "[T] soft-reboot verify-and-exec shell (RC_DIGEST_CHANGED=$RC)"
printf 'pinned daemon bytes\n' > "$WORK/ksud"
REAL=$(sha256sum "$WORK/ksud" | cut -d' ' -f1)
OTHER=$(printf 'the root manager build\n' > "$WORK/other"; sha256sum "$WORK/other" | cut -d' ' -f1)

check "digest matches -> reaches exec"            "$WORK/ksud"  "$REAL"  0    yes
# The case this whole re-check exists for: the path now holds other bytes.
check "path replaced since the check -> refuses"   "$WORK/ksud"  "$OTHER" "$RC" no
check "file gone -> refuses"                      "$WORK/nope"  "$REAL"  "$RC" no
# A path this app cannot read must refuse rather than skip the comparison.
: > "$WORK/unreadable"; chmod 000 "$WORK/unreadable" 2>/dev/null || true
if [ "$(id -u)" != "0" ]; then
    check "unreadable -> refuses"                  "$WORK/unreadable" "$REAL" "$RC" no
else
    echo "  skip - unreadable case (running as root)"
fi
# grep -qx, not grep -q: a digest that CONTAINS the pinned one is not the pinned one.
printf 'x\n' > "$WORK/sup"
set +e
sh -c "echo '${REAL}extra' | grep -qx '$REAL' || exit $RC" >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" = "$RC" ]; then
    pass=$((pass + 1)); echo "  ok   - a superstring of the pinned digest refuses"
else
    fail=$((fail + 1)); echo "  FAIL - a superstring of the pinned digest was accepted"
fi

echo ""
echo "soft-reboot shell: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
