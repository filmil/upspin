#!/bin/bash
# Copyright 2026 The Upspin Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# Checks that release builds say which build they are
# (https://github.com/filmil/upspin/issues/120), on the host platform:
#
#   - an ordinary build of cmd/upspin prints "devel" for -version;
#   - a --config=release build prints the commit and its time, no release
#     line on a commit without a release tag, and no unexpanded stamp key.
#
# Run from the repository root of a clean checkout, as CI does.
set -euo pipefail

# version_of prints the -version output of cmd/upspin built with the given
# flags, and checks that it exits with status 2, as upspin -version does.
version_of() {
	bazel build "$@" //cmd/upspin
	local files
	files=$(bazel cquery "$@" --output=files //cmd/upspin)
	if [[ $(wc -l <<<"$files") -ne 1 ]]; then
		echo "FAIL: cmd/upspin has more than one output: $files" >&2
		exit 1
	fi
	local status=0
	out=$("$files" -version) || status=$?
	if [[ $status -ne 2 ]]; then
		echo "FAIL: upspin -version exited with $status, want 2" >&2
		exit 1
	fi
}

fail() {
	echo "FAIL: $1:" >&2
	echo "$out" >&2
	exit 1
}

version_of
[[ "$out" == "devel" ]] || fail "an unstamped build does not print devel"

version_of --config=release
commit=$(git rev-parse HEAD)
built=$(TZ=UTC git show -s --format=%cd --date=format-local:'%b %e %H:%M:%S %Y UTC' HEAD)
grep -qx "Git hash:   $commit" <<<"$out" || fail "a release build does not print the commit $commit"
grep -qx "Build time: $built" <<<"$out" || fail "a release build does not print the commit time $built"
if ! git describe --tags --exact-match --match 'v[0-9]*' HEAD >/dev/null 2>&1; then
	grep -q '^Release:' <<<"$out" && fail "an untagged release build prints a release"
fi
grep -q '{' <<<"$out" && fail "a release build prints an unexpanded stamp key"
echo "PASS: a release build prints"
echo "$out"
