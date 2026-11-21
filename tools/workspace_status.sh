#!/bin/sh
# Copyright 2026 The Upspin Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# Bazel's workspace status command for --config=release builds (.bazelrc).
# Its stable keys go into -version through version/BUILD.bazel:
#
#   STABLE_GIT_COMMIT   the commit being built, with "-dirty" when git status
#                       lists a changed tracked file or fails
#   STABLE_BUILD_TIME   that commit's time, so that a rebuild is identical
#   STABLE_RELEASE_TAG  the release tag (v<digits>...) at that commit, or
#                       empty
#
# and one volatile key, which is not stamped into anything, so that its
# changes rebuild nothing:
#
#   GIT_STATUS          why the commit is "-dirty": the entries of
#                       git status, or its error, joined by ";"; empty
#                       when clean. The release job prints it.
#
# Outside a git checkout it prints the keys empty; version.Version() then
# prints "devel". tools/workspace_status_test.go tests it.

commit=$(git rev-parse HEAD 2>/dev/null) || commit=""
time=""
tag=""
status=""
if [ -n "$commit" ]; then
	time=$(git show -s --format=%cI HEAD)
	# --no-optional-locks: do not take .git/index.lock to save the
	# refreshed index, which would race with other git commands. Only
	# stdout decides; a warning on stderr does not make a tree dirty.
	if ! status=$(git --no-optional-locks status --porcelain --untracked-files=no 2>/dev/null); then
		err=$(git --no-optional-locks status --porcelain --untracked-files=no 2>&1 >/dev/null)
		status="git status failed: $err"
	fi
	[ -n "$status" ] && commit="$commit-dirty"
	tag=$(git describe --tags --exact-match --match 'v[0-9]*' HEAD 2>/dev/null) || tag=""
fi
# printf, not echo: git status escapes unusual file names with
# backslashes, which echo in some shells would interpret.
printf 'STABLE_GIT_COMMIT %s\n' "$commit"
printf 'STABLE_BUILD_TIME %s\n' "$time"
printf 'STABLE_RELEASE_TAG %s\n' "$tag"
printf 'GIT_STATUS %s\n' "$(printf '%s\n' "$status" | paste -sd ';' -)"
