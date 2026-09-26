#!/bin/sh
# resolve_dispatch_tag.sh - decide WHICH tag a release run is publishing.
#
#   tools/resolve_dispatch_tag.sh <input_tag> <ref_type> <ref_name> <version_name>
#
# Prints the tag on stdout and exits 0, or exits 1 with the reason on stderr as a
# GitHub Actions ::error:: annotation.
#
# It exists because the obvious one-liner is wrong in a way that only shows up on
# a manual dispatch:
#
#     TAG="${{ inputs.tag }}"
#     [ -n "$TAG" ] || TAG="${GITHUB_REF_NAME}"
#
# On a TAG PUSH, GITHUB_REF_NAME is the tag - correct. On a workflow_dispatch it
# is the BRANCH, so a dispatch that left the tag box empty resolved to `main`,
# and `gh release create main` would have created a tag literally named after the
# default branch and published the release under it. The tag/versionName check
# caught that, which is how it was found; this removes the trap instead of relying
# on the check to keep catching it.
#
# The rule: an explicit input wins; a tag push uses its own tag; a dispatch with
# no input derives the tag from the tree it is building (`v` + versionName), which
# is the only value that cannot disagree with the artifacts. Anything else is
# undecidable and refuses.
#
# Unit-tested off-CI by tools/tests/test_resolve_release_tag.sh.
set -eu

INPUT="${1-}"
REF_TYPE="${2-}"
REF_NAME="${3-}"
VER="${4-}"

trimmed=$(printf '%s' "$INPUT" | tr -d '[:space:]')
if [ -n "$trimmed" ]; then
    printf '%s\n' "$trimmed"
    exit 0
fi

if [ "$REF_TYPE" = "tag" ]; then
    if [ -z "$REF_NAME" ]; then
        echo "::error::the run is on a tag ref but GITHUB_REF_NAME is empty." >&2
        exit 1
    fi
    printf '%s\n' "$REF_NAME"
    exit 0
fi

# A manual dispatch from a branch. Deriving the tag from versionName keeps the
# tag, the assets, their versionCode and the release title describing one version
# by construction - the branch name never enters into it.
if [ -n "$VER" ]; then
    echo "no tag input given on a $REF_TYPE ref; using v$VER from app/build.gradle.kts" >&2
    printf 'v%s\n' "$VER"
    exit 0
fi

echo "::error::cannot decide which tag to publish: no tag input, the ref is a" >&2
echo "::error::$REF_TYPE rather than a tag, and no versionName was read from" >&2
echo "::error::app/build.gradle.kts. Refusing rather than guessing." >&2
exit 1
