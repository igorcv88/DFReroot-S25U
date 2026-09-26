#!/bin/sh
# resolve_release_tag.sh - decide whether it is safe to publish <tag> from <sha>.
#
#   tools/resolve_release_tag.sh <owner/repo> <tag> <expected_sha> [version_name]
#
# Prints TAG_EXISTS=0 (absent, will be created) or TAG_EXISTS=1 (exists and
# already points at <expected_sha>) and exits 0. Exits 1 on anything else, with
# the reason on stderr as a GitHub Actions ::error:: annotation.
#
# It lives here rather than inline in release.yml for two reasons: the release
# workflow has to run it TWICE - once before the build and again immediately
# before publishing, because the tag can appear during the several minutes in
# between - and shell that decides whether artifacts get attached to the right
# commit is worth testing off-CI. tools/tests/test_resolve_release_tag.sh drives
# every branch against a stubbed gh.
#
# With <version_name> (app/build.gradle.kts `versionName`) it ALSO refuses a tag
# that does not spell that exact version. Nothing else compared the two: the
# release names its assets and its title from versionName while it is published
# under the dispatched tag, so dispatching v2.0.5-zzic from a tree still at
# 2.0.4-zzic produced a release tagged for a version whose APKs carry the
# previous versionCode - a mismatch no offline gate could see, on the one
# workflow the owner is allowed to spend. The comparison is exact and runs
# before any network call, so it costs nothing and fails in the first seconds.
#
# Requires `gh` (authenticated via GH_TOKEN) and `jq` on PATH.
set -eu

REPO="${1:?usage: resolve_release_tag.sh <owner/repo> <tag> <expected_sha>}"
TAG="${2:?missing tag}"
WANT="${3:?missing expected sha}"
VER="${4:-}"

if [ -n "$VER" ]; then
    if [ "$TAG" != "v$VER" ]; then
        echo "::error::tag $TAG does not match app/build.gradle.kts versionName" >&2
        echo "::error::$VER (expected tag v$VER)." >&2
        echo "::error::Refusing before the build: the APKs, their versionCode and" >&2
        echo "::error::the release title would describe a different version than the" >&2
        echo "::error::tag they are published under. Bump versionName/versionCode, or" >&2
        echo "::error::dispatch the tag that matches this tree." >&2
        exit 1
    fi
fi

# Emptiness of stdout cannot decide whether the tag exists: `gh api` writes its
# error BODY to stdout, so a 404 leaves a non-empty {"message":"Not Found",...}
# and `[ -n "$out" ]` reads as "the tag exists", after which jq yields the string
# "null". That made publishing a NEW tag impossible. Key on the exit status.
set +e
REF_JSON=$(gh api "repos/$REPO/git/ref/tags/$TAG" 2>/dev/null)
REF_RC=$?
set -e

if [ "$REF_RC" -eq 0 ]; then
    SHA=$(printf '%s' "$REF_JSON" | jq -r '.object.sha // empty')
    TYPE=$(printf '%s' "$REF_JSON" | jq -r '.object.type // empty')
    # An annotated tag points at a tag object; dereference to the commit.
    if [ "$TYPE" = "tag" ]; then
        SHA=$(gh api "repos/$REPO/git/tags/$SHA" --jq '.object.sha' 2>/dev/null || true)
    fi
    if [ -z "$SHA" ] || [ "$SHA" = "null" ]; then
        echo "::error::$TAG resolved but no commit sha could be read from it." >&2
        printf '%s\n' "$REF_JSON" >&2
        exit 1
    fi
    if [ "$SHA" != "$WANT" ]; then
        echo "::error::tag $TAG points at $SHA but this run built $WANT." >&2
        echo "::error::Refusing: publishing here would attach this build's artifacts" >&2
        echo "::error::to a release for a different commit. Re-run from the tag itself," >&2
        echo "::error::or publish a new tag." >&2
        exit 1
    fi
    echo "TAG_EXISTS=1"
    exit 0
fi

# Distinguish "absent" from "could not tell". A transport, auth or rate-limit
# failure must NOT be read as absent: that would create a tag over one that
# already exists, which is exactly what this check is here to prevent.
if printf '%s' "$REF_JSON" | jq -e '.status == "404" or .message == "Not Found"' \
        >/dev/null 2>&1; then
    echo "TAG_EXISTS=0"
    exit 0
fi

echo "::error::cannot determine whether tag $TAG exists (gh api rc=$REF_RC)." >&2
echo "::error::Refusing rather than guessing." >&2
printf '%s\n' "$REF_JSON" >&2
exit 1
