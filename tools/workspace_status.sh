#!/bin/sh
# Copyright 2026 The Upspin Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# Bazel's workspace status command (.bazelrc). Bazel puts these keys into
# the binaries only when a build uses --stamp, as release builds do; see
# version/BUILD.bazel. Ordinary builds ignore them and print "devel".
#
#   STABLE_GIT_COMMIT   the commit being built
#   STABLE_BUILD_TIME   that commit's time, so that a rebuild is identical
#   STABLE_RELEASE_TAG  the release tag at that commit, if there is one
#
# Outside a git checkout it prints nothing, and the build is unstamped.

commit=$(git rev-parse HEAD 2>/dev/null) || exit 0
echo "STABLE_GIT_COMMIT $commit"
echo "STABLE_BUILD_TIME $(git show -s --format=%cI HEAD)"
tag=$(git describe --tags --exact-match HEAD 2>/dev/null) && echo "STABLE_RELEASE_TAG $tag"
exit 0
