#!/bin/sh
# Host tests for tools/resolve_release_tag.sh against a stubbed `gh`. No network,
# no CI minutes: this is the shell that decides whether a signed build gets
# attached to the right commit, so every branch is exercised off-device.
set -eu
cd "$(dirname "$0")/../.."
SUT=tools/resolve_release_tag.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

SHA_OK=e1cc3a4afcb05b6aaef478ccd47fc7957965664a
SHA_OTHER=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef

pass=0
fail=0

# $1 name  $2 gh mode  $3 expected exit  $4 expected stdout (may be empty)
check() {
    name="$1"; mode="$2"; want_rc="$3"; want_out="$4"
    cat > "$WORK/bin/gh" <<EOF
#!/bin/sh
case "$mode" in
  absent)
    echo '{"message":"Not Found","documentation_url":"https://docs.github.com","status":"404"}'
    exit 1 ;;
  match)
    echo '{"object":{"sha":"$SHA_OK","type":"commit"}}'; exit 0 ;;
  mismatch)
    echo '{"object":{"sha":"$SHA_OTHER","type":"commit"}}'; exit 0 ;;
  annotated_match)
    case "\$*" in
      *git/tags/*) echo '$SHA_OK'; exit 0 ;;
    esac
    echo '{"object":{"sha":"aaaa111122223333444455556666777788889999","type":"tag"}}'
    exit 0 ;;
  annotated_mismatch)
    case "\$*" in
      *git/tags/*) echo '$SHA_OTHER'; exit 0 ;;
    esac
    echo '{"object":{"sha":"aaaa111122223333444455556666777788889999","type":"tag"}}'
    exit 0 ;;
  no_sha)
    echo '{"object":{}}'; exit 0 ;;
  transport)
    echo 'error connecting to api.github.com' >&2; exit 1 ;;
  ratelimit)
    echo '{"message":"API rate limit exceeded","status":"403"}'; exit 1 ;;
esac
EOF
    chmod +x "$WORK/bin/gh"
    set +e
    out=$(PATH="$WORK/bin:$PATH" sh "$SUT" owner/repo "${TAG_ARG:-v9.9.9}" "$SHA_OK" \
        ${VER_ARG+"$VER_ARG"} 2>"$WORK/err")
    rc=$?
    set -e
    ok=1
    [ "$rc" = "$want_rc" ] || ok=0
    [ "$out" = "$want_out" ] || ok=0
    if [ "$ok" = 1 ]; then
        pass=$((pass + 1)); printf '  ok   - %s (rc=%s out=%s)\n' "$name" "$rc" "${out:-<none>}"
    else
        fail=$((fail + 1))
        printf '  FAIL - %s: rc=%s want %s, out=%s want %s\n' \
            "$name" "$rc" "$want_rc" "${out:-<none>}" "${want_out:-<none>}"
        sed 's/^/         /' "$WORK/err"
    fi
}

echo "[T] resolve_release_tag.sh"

# The case that made publishing impossible: gh writes its 404 body to stdout, so
# a non-empty check read "absent" as "exists" and jq produced the string "null".
check "absent (404 body on stdout) -> create"        absent             0 "TAG_EXISTS=0"
check "exists at this commit -> update"              match              0 "TAG_EXISTS=1"
check "exists at another commit -> refuse"           mismatch           1 ""
check "annotated tag derefs to this commit"          annotated_match    0 "TAG_EXISTS=1"
check "annotated tag derefs elsewhere -> refuse"     annotated_mismatch 1 ""
check "resolved but no sha -> refuse"                no_sha             1 ""
# "Could not tell" must never fall through to the create path: that would create
# a tag over one that already exists, the very thing this check prevents.
check "gh unreachable -> refuse, not 'absent'"       transport          1 ""
check "rate limited (403) -> refuse, not 'absent'"   ratelimit          1 ""

# The tag and app/build.gradle.kts versionName were never compared, so a
# dispatch could publish a v2.0.5 tag whose assets are all 2.0.4. The refusal is
# offline and happens before the build: with `mismatch` stubbed for gh, an
# agreeing version still reaches the (refusing) sha comparison, which proves the
# version check did not simply swallow the call.
VER_ARG=9.9.9 check "version agrees with the tag -> proceeds to the sha check" \
    mismatch 1 ""
VER_ARG=9.9.9 check "version agrees with the tag -> publishes"  match    0 "TAG_EXISTS=1"
VER_ARG=2.0.4-zzic check "tag disagrees with versionName -> refuse" match 1 ""
TAG_ARG=v2.0.4-zzic VER_ARG=2.0.4-zzic \
    check "matching non-trivial version pair is accepted"  match  0 "TAG_EXISTS=1"
# No version argument at all must keep the old behaviour rather than refusing.
check "no version argument -> unchanged behaviour"     match  0 "TAG_EXISTS=1"

echo ""
echo "$((pass)) / $((pass + fail)) checks passed, $fail failed"
[ "$fail" = 0 ]
