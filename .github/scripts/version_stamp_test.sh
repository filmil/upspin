#!/bin/bash
# Copyright 2026 The Upspin Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# Checks that the release builds say which build they are
# (https://github.com/filmil/upspin/issues/120): an ordinary build of
# cmd/upspin prints "devel" for -version, and a --stamp build, as the
# release job makes, prints the commit being built.
#
# Run from the repository root, as CI does. Takes any extra bazel flags
# for the stamped build, such as --platforms.
set -euo pipefail

version_of() {
	local bin
	bin=$(bazel cquery "$@" --output=files //cmd/upspin 2>/dev/null)
	# upspin -version exits with status 2 after printing.
	"$bin" -version || true
}

bazel build //cmd/upspin
got=$(version_of)
if [[ "$got" != "devel" ]]; then
	echo "FAIL: an unstamped build prints:" >&2
	echo "$got" >&2
	exit 1
fi

bazel build --stamp "$@" //cmd/upspin
got=$(version_of --stamp "$@")
want=$(git rev-parse HEAD)
if ! grep -qx "Git hash:   $want" <<<"$got"; then
	echo "FAIL: a stamped build does not print the commit $want:" >&2
	echo "$got" >&2
	exit 1
fi
echo "PASS: stamped build prints"
echo "$got"
