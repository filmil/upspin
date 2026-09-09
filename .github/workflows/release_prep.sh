#!/usr/bin/env bash
# Builds the release archives and prints the release notes to stdout.
#
# Called by bazel-contrib/.github/.github/workflows/release_ruleset.yaml, which
# requires this exact path and reads the release notes from stdout.
set -o errexit -o nounset -o pipefail

TAG="$1"
VERSION="${TAG#v}"
REPO_NAME="upspin"

# The registry entry points at this one. `.bcr/source.template.json` gives
# `url` as `{TAG}.tar.gz` and `strip_prefix` as `{REPO}-{VERSION}`, so the
# archive is named after the tag and holds one top level directory named after
# the version. `git archive` is right here, because it is what built this
# archive before this script replaced it.
git archive --format=tar.gz --prefix="${REPO_NAME}-${VERSION}/" \
  -o "${TAG}.tar.gz" HEAD

# A convenience archive, not referenced by any registry entry. It keeps the
# exclusions thedoctor0/zip-release used, so its contents do not change.
#
# `--symlinks` stops `zip` following a symlink and storing what it points at.
# `zip` walks the tree before it applies `-x`, so an exclusion does not stop
# the walk, and with bazel's convenience symlinks present the walk descends the
# whole output base.
zip --quiet --symlinks --recurse-paths "${REPO_NAME}-${TAG}.zip" . \
  -x '*.git*' '/*node_modules/*' '.editorconfig' '*bazel-*' \
     'release_notes.txt' "${REPO_NAME}-${TAG}.zip"

cat <<NOTES
## Using Bzlmod

\`\`\`starlark
bazel_dep(name = "upspin", version = "${VERSION}")
\`\`\`
NOTES
