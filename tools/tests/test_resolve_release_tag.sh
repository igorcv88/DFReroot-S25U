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

# --- tools/resolve_release_version.sh ---------------------------------------
# The version is no longer written anywhere in the tree: this is what decides the
# tag, the versionName and the versionCode of both APKs. Two traps it removes:
# GITHUB_REF_NAME is the BRANCH on a workflow_dispatch (an empty tag box used to
# resolve to "main", and `gh release create main` would have created a tag named
# after the default branch), and a hand-edited version could disagree with the
# tag it shipped under.
echo ""
echo "[T] resolve_release_version.sh"
SUT2=tools/resolve_release_version.sh

TAGS="$WORK/tags"
# v2.0.9 vs v2.0.10 is the case lexical sorting gets wrong: it would bump 2.0.9
# again and collide with a published tag, several minutes into the build.
cat > "$TAGS" <<'TAGLIST'
v1.0
main
v2.0.4-zzic
v2.0.5-zzic
v2.0.9-zzic
v2.0.10-zzic
TAGLIST

# $1 name  $2 expected rc  $3 expected stdout (newline-joined)  rest: argv
vcheck() {
    name="$1"; want_rc="$2"; want_out="$3"; shift 3
    set +e
    out=$(sh "$SUT2" "$@" 2>"$WORK/err2")
    rc=$?
    set -e
    if [ "$rc" = "$want_rc" ] && [ "$out" = "$want_out" ]; then
        pass=$((pass + 1)); printf '  ok   - %s (rc=%s)\n' "$name" "$rc"
    else
        fail=$((fail + 1))
        printf '  FAIL - %s: rc=%s want %s\n' "$name" "$rc" "$want_rc"
        printf '         got  [%s]\n         want [%s]\n' "$out" "$want_out"
        sed 's/^/         /' "$WORK/err2"
    fi
}

DERIVED="TAG=v2.0.11-zzic
VER=2.0.11-zzic
VERSION_CODE=20011
VERSION_SOURCE=derived"

INPUT309="TAG=v3.0.9-zzic
VER=3.0.9-zzic
VERSION_CODE=30009
VERSION_SOURCE=input"

vcheck "empty dispatch bumps the greatest tag, NOT the branch" \
    0 "$DERIVED" "" branch main "$TAGS"
vcheck "a branch called v1.0 is still not used as the tag" \
    0 "$DERIVED" "" branch v1.0 "$TAGS"
vcheck "whitespace-only input counts as empty" \
    0 "$DERIVED" "   " branch main "$TAGS"
vcheck "explicit input wins over the derivation" \
    0 "$INPUT309" v3.0.9-zzic branch main "$TAGS"
vcheck "input is trimmed" \
    0 "$INPUT309" " v3.0.9-zzic " branch main "$TAGS"
vcheck "tag push publishes its own tag" 0 "TAG=v2.0.6-zzic
VER=2.0.6-zzic
VERSION_CODE=20006
VERSION_SOURCE=tag-push" "" tag v2.0.6-zzic "$TAGS"
vcheck "a suffixless version is accepted and keeps no suffix" 0 "TAG=v4.1.2
VER=4.1.2
VERSION_CODE=40102
VERSION_SOURCE=input" v4.1.2 branch main "$TAGS"

# The APKs take their versionName FROM this string, so a malformed tag is a
# malformed shipped identity, not a malformed label. Validate, never trust.
vcheck "input without the v prefix -> refuse"   1 "" 2.0.6-zzic  branch main "$TAGS"
vcheck "input missing the patch part -> refuse" 1 "" v2.1-zzic   branch main "$TAGS"
vcheck "a branch name as the input -> refuse"   1 "" main        branch main "$TAGS"
vcheck "tag push of a malformed tag -> refuse"  1 "" "" tag release-2 "$TAGS"
vcheck "tag ref with no name -> refuse"         1 "" "" tag ""        "$TAGS"
# Leading zeros would give v2.8.9 and v2.08.09 one versionCode for two different
# versionNames - the same build as far as the device is concerned.
vcheck "leading zeros -> refuse"                1 "" v2.08.09-zzic branch main "$TAGS"
# minor/patch above 99 would wrap into the next major's code range, so a NEWER
# release could ship a LOWER versionCode and be refused as a downgrade.
vcheck "minor over the scheme limit -> refuse"  1 "" v2.100.0-zzic branch main "$TAGS"
vcheck "patch over the scheme limit -> refuse"  1 "" v2.0.100-zzic branch main "$TAGS"

# Nothing to bump from, and nothing to guess with.
: > "$WORK/empty"
vcheck "no versioned tag to bump -> refuse"     1 "" "" branch main "$WORK/empty"
vcheck "no tag list on the derive path -> refuse" 1 "" "" branch main
vcheck "tag list does not exist -> refuse"      1 "" "" branch main "$WORK/nope"
# Which -zzic/-zzid line the next patch continues is undecidable, and the suffix
# is carried into the shipped versionName.
printf 'v2.0.5-zzic\nv2.0.5-zzid\n' > "$WORK/ambig"
vcheck "two suffixes on the greatest version -> refuse" 1 "" "" branch main "$WORK/ambig"

echo ""
echo "$((pass)) / $((pass + fail)) checks passed, $fail failed"
[ "$fail" = 0 ]
