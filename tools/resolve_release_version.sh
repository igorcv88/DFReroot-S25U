#!/bin/sh
# resolve_release_version.sh - decide the version a release run publishes.
#
#   tools/resolve_release_version.sh <input_tag> <ref_type> <ref_name> [<tags_file>]
#
# Prints, on stdout, four assignments suitable for `>> "$GITHUB_ENV"`:
#
#   TAG=v2.0.6-zzic        the git tag the release is published under
#   VER=2.0.6-zzic         versionName compiled into BOTH APKs
#   VERSION_CODE=20006     versionCode compiled into BOTH APKs
#   VERSION_SOURCE=derived where the answer came from (input|tag-push|derived)
#
# Exits 1 with the reason on stderr (as ::error:: annotations) rather than
# guessing.
#
# ## Why this exists
#
# versionCode/versionName used to be literals in app/build.gradle.kts and
# installer/build.gradle.kts, and a release meant hand-editing four numbers in
# two files, in the right order, before dispatching a tag that had to spell the
# same string. Every part of that was a footgun and each one fired at least once:
# the installer was left at the previous version while the app moved; a dispatch
# named v2.0.5 for a tree still at 2.0.4; a dispatch named v2.0.5 for a tree
# already at 2.0.5-zzic. The guards caught them, but only after a runner had been
# spent - and the owner is allowed exactly one workflow.
#
# So the version is no longer written down anywhere in the tree. It is derived
# here, once per run, and injected into both modules from one environment pair
# (see the root build.gradle.kts). Drift between the tag, the two APKs, the asset
# filenames and the release title is not caught any more; it is unrepresentable,
# because there is only one value and nothing to type.
#
# ## The rules
#
#   1. An explicit tag input wins. It must spell a full version, because the
#      APKs' versionName is now taken FROM it: a typo'd tag is not a typo'd
#      label any more, it is the shipped identity. So it is validated, not
#      trusted.
#   2. A tag push publishes its own tag, validated the same way.
#   3. A dispatch from a branch with an empty tag box derives the NEXT patch
#      version from the tags that already exist. This is the common case and the
#      one the owner asked for: dispatch the workflow, get the next version.
#      GITHUB_REF_NAME is the BRANCH on a dispatch, so it is never used as a tag -
#      that mistake once resolved to `main` and would have created a tag named
#      after the default branch.
#   4. Anything else refuses.
#
# versionCode is derived from the version rather than counted, so it is a pure
# function of the name: major*10000 + minor*100 + patch. Two artifacts with the
# same versionName can therefore never carry different versionCodes, and the
# sequence is monotonic in the version for as long as minor and patch stay below
# 100 - which is checked, because silently wrapping would let a NEWER release
# ship a LOWER versionCode and be refused as a downgrade on the device.
#
# Unit-tested off-CI by tools/tests/test_resolve_release_tag.sh.
set -eu

INPUT="${1-}"
REF_TYPE="${2-}"
REF_NAME="${3-}"
TAGS_FILE="${4-}"

err() { echo "::error::$*" >&2; }

# A version this repository may ship: vMAJOR.MINOR.PATCH with an optional
# firmware suffix (the shipped one is -zzic). The suffix is not hardcoded: it is
# carried over from the tag being bumped, so retargeting the fork at another
# firmware does not need this file edited.
# Each component is 0 or has no leading zero: v2.8.9 and v2.08.09 would otherwise
# be two different versionNames sharing one versionCode, which the device reads
# as the same build.
VALID='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[A-Za-z0-9][A-Za-z0-9.]*)?$'

# Emit TAG/VER/VERSION_CODE for an already-validated tag, or refuse if the
# numbers do not fit the versionCode scheme. The fit is checked here, on every
# path, and not only where the numbers are derived: an explicit v2.100.0 input
# would otherwise collide with v3.0.0's code.
emit() {
    tag="$1"; source="$2"
    ver=${tag#v}
    triple=${ver%%-*}
    major=$(printf '%s' "$triple" | cut -d. -f1)
    minor=$(printf '%s' "$triple" | cut -d. -f2)
    patch=$(printf '%s' "$triple" | cut -d. -f3)
    if [ "$minor" -gt 99 ] || [ "$patch" -gt 99 ] || [ "$major" -gt 999 ]; then
        err "$tag does not fit the versionCode scheme (major*10000 + minor*100 +"
        err "patch): minor and patch must stay below 100 and major below 1000, or"
        err "a newer release would ship a LOWER versionCode than an older one and"
        err "the device would refuse it as a downgrade. Bump the major/minor"
        err "instead, or change the scheme deliberately."
        exit 1
    fi
    code=$(( (major * 10000) + (minor * 100) + patch ))
    printf 'TAG=%s\n' "$tag"
    printf 'VER=%s\n' "$ver"
    printf 'VERSION_CODE=%s\n' "$code"
    printf 'VERSION_SOURCE=%s\n' "$source"
    exit 0
}

reject_shape() {
    err "$1 is not a version this release can publish."
    err "Expected vMAJOR.MINOR.PATCH with an optional suffix, e.g. v2.0.6-zzic."
    err "The APKs' versionName is taken from this string, so it is validated"
    err "rather than trusted: a typo here would be the shipped identity."
    case "$1" in
        v*) ;;
        *)  err "(\"$1\" does not even start with 'v'.)" ;;
    esac
    exit 1
}

trimmed=$(printf '%s' "$INPUT" | tr -d '[:space:]')
if [ -n "$trimmed" ]; then
    printf '%s' "$trimmed" | grep -Eq "$VALID" || reject_shape "$trimmed"
    emit "$trimmed" input
fi

if [ "$REF_TYPE" = "tag" ]; then
    if [ -z "$REF_NAME" ]; then
        err "the run is on a tag ref but GITHUB_REF_NAME is empty."
        exit 1
    fi
    printf '%s' "$REF_NAME" | grep -Eq "$VALID" || reject_shape "$REF_NAME"
    emit "$REF_NAME" tag-push
fi

# --- the derive path: a dispatch from a branch, no tag typed -----------------
if [ -z "$TAGS_FILE" ]; then
    err "no tag input, the ref is a $REF_TYPE rather than a tag, and no list of"
    err "existing tags was supplied to derive the next version from. Refusing"
    err "rather than guessing a version."
    exit 1
fi
if [ "$TAGS_FILE" = "-" ]; then
    tags=$(cat)
else
    [ -f "$TAGS_FILE" ] || { err "tag list $TAGS_FILE does not exist."; exit 1; }
    tags=$(cat "$TAGS_FILE")
fi

# The greatest existing version, compared NUMERICALLY on the triple. Lexical
# order would put v2.0.9 above v2.0.10, so the next release would reuse a
# published tag - which resolve_release_tag.sh would then refuse, after the
# build. Sort on a zero-padded key instead.
best=$(printf '%s\n' "$tags" | tr -d '\r' | grep -E "$VALID" 2>/dev/null | awk '
    {
        v = substr($0, 2)
        sub(/-.*$/, "", v)
        split(v, p, ".")
        printf "%05d%05d%05d %s\n", p[1], p[2], p[3], $0
    }' | sort | tail -1)

if [ -z "$best" ]; then
    err "no existing tag names a version (vMAJOR.MINOR.PATCH), so there is"
    err "nothing to bump from. Dispatch with an explicit tag for the first one."
    exit 1
fi

key=${best%% *}
bestname=${best#* }

# Two tags on the same triple with different suffixes (v2.0.5-zzic and
# v2.0.5-zzid) leave "the next patch of WHAT" undecidable, and the suffix is
# carried into the shipped versionName. Refuse instead of taking whichever one
# sorted last.
ties=$(printf '%s\n' "$tags" | tr -d '\r' | grep -E "$VALID" 2>/dev/null | awk -v k="$key" '
    {
        v = substr($0, 2)
        sub(/-.*$/, "", v)
        split(v, p, ".")
        if (sprintf("%05d%05d%05d", p[1], p[2], p[3]) == k) print $0
    }' | sort -u | wc -l)
if [ "$ties" -gt 1 ]; then
    err "several tags name the same version with different suffixes:"
    printf '%s\n' "$tags" | grep -E "$VALID" | sed 's/^/::error::  /' >&2
    err "which of them the next version continues is undecidable. Dispatch with"
    err "an explicit tag."
    exit 1
fi

suffix=""
case "$bestname" in *-*) suffix="-${bestname#*-}" ;; esac
bt=${bestname#v}; bt=${bt%%-*}
bmajor=$(printf '%s' "$bt" | cut -d. -f1)
bminor=$(printf '%s' "$bt" | cut -d. -f2)
bpatch=$(printf '%s' "$bt" | cut -d. -f3)
next="v${bmajor}.${bminor}.$(( bpatch + 1 ))${suffix}"

# It cannot be in the list - it is greater than the greatest - unless the
# comparison above is wrong. Assert it anyway: this is the one value nothing
# downstream can sanity-check before the build is spent.
if printf '%s\n' "$tags" | tr -d '\r' | grep -qx -- "$next"; then
    err "derived $next from $bestname but that tag already exists; the version"
    err "comparison is wrong. Refusing."
    exit 1
fi

echo "no tag input on a $REF_TYPE ref: bumping $bestname to $next" >&2
emit "$next" derived
