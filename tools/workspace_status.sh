#!/bin/sh
# Copyright 2026 The Upspin Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# Bazel's workspace status command for --config=release builds (.bazelrc).
# Its keys go into -version through version/BUILD.bazel:
#
#   STABLE_GIT_COMMIT   the commit being built, with "-dirty" when the
#                       working tree has uncommitted changes
#   STABLE_BUILD_TIME   that commit's time, so that a rebuild is identical
#   STABLE_RELEASE_TAG  the release tag (v<digits>...) at that commit, or
#                       empty
#   STABLE_GIT_STATUS   what makes the commit "-dirty": the changed tracked
#                       files, or git's error; empty when clean
#
# Outside a git checkout it prints the keys empty; version.Version() then
# prints "devel".

commit=$(git rev-parse HEAD 2>/dev/null) || commit=""
time=""
tag=""
status=""
if [ -n "$commit" ]; then
	time=$(git show -s --format=%cI HEAD)
	# The tracked files that differ from HEAD, as git status (which
	# refreshes the index) sees them, or git's error if it fails.
	status=$(git status --porcelain --untracked-files=no 2>&1) || status="git status failed: $status"
	[ -n "$status" ] && commit="$commit-dirty"
	tag=$(git describe --tags --exact-match --match 'v[0-9]*' HEAD 2>/dev/null) || tag=""
fi
echo "STABLE_GIT_COMMIT $commit"
echo "STABLE_BUILD_TIME $time"
echo "STABLE_RELEASE_TAG $tag"
# Why the commit is "-dirty", for the release job to print: one line, with
# the entries of git status separated by "; ".
echo "STABLE_GIT_STATUS $(printf '%s' "$status" | tr '\n' ';' | sed 's/;/; /g')"
