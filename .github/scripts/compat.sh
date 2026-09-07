#!/bin/bash
# Builds the upspin binary at an older commit and runs the compatibility
# test in test/compat against it, so that "stored data written by the
# old binary stays readable, and the reverse" is checked by a machine.
#
# Arguments:
#   $1  the older commit, for example the base of a pull request.
#
# Exit status:
#   0  the old and new binaries read each other's files
#   1  the test failed
#   2  the old binary could not be built
set -u
old=${1:-}
if [[ -z "$old" ]]; then
	echo "usage: $0 <commit>" >&2
	exit 2
fi
worktree=$(mktemp -d)
trap 'git worktree remove --force "$worktree" >/dev/null 2>&1' EXIT
git worktree add --detach "$worktree" "$old" >/dev/null 2>&1 || { echo "compat: cannot check out $old" >&2; exit 2; }
echo "compat: building upspin at $(git -C "$worktree" log -1 --format='%h %s')"
(cd "$worktree" && bazel build //cmd/upspin >/dev/null 2>&1) || { echo "compat: build of the old binary failed" >&2; exit 2; }
oldbin=$(cd "$worktree" && readlink -f bazel-bin/cmd/upspin/upspin_/upspin)
cp "$oldbin" "$worktree/upspin-old"
echo "compat: old binary at $worktree/upspin-old"
bazel test //test/compat:compat_test --test_env=UPSPIN_COMPAT_OLD="$worktree/upspin-old" --test_output=errors --nocache_test_results
