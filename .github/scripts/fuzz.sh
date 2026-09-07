#!/bin/bash
# Runs every fuzz target for a fixed time through Bazel's Go toolchain
# (Bazel itself does not drive the fuzz engine), then copies the corpus
# the engine grew into testdata/fuzz so that it can be committed.
#
# Arguments:
#   $1  fuzz time per target, in Go duration syntax, for example 60s.
#       Use 30s or more: the engine needs a few seconds to gather baseline
#       coverage and to stop its workers, and a shorter budget ends in a
#       spurious "context deadline exceeded" failure.
#
# Exit status:
#   0  every target ran to its time without a failure
#   1  a target found a failing input; it is written under testdata/fuzz
set -u
fuzztime=${1:-60s}
# package target pairs; keep in step with the Fuzz functions in the tree.
targets="
pack/ee FuzzUnmarshal
factotum FuzzParsePublicKey
factotum FuzzParseEncapsulationKey
factotum FuzzParsePrivateKey
factotum FuzzSecret2Archive
key/keygen FuzzSecretFromProquint
"
gocache=$(bazel run @rules_go//go -- env GOCACHE 2>/dev/null | tail -1)
status=0
while read -r pkg name; do
	[[ -z "$pkg" ]] && continue
	echo "=== $pkg $name ($fuzztime)"
	if ! bazel run @rules_go//go -- test -run='^$' -fuzz="^${name}\$" -fuzztime="$fuzztime" "./$pkg"; then
		status=1
	fi
	# The engine keeps interesting inputs under GOCACHE; fold them into
	# the committed corpus so a later run starts from them.
	src="$gocache/fuzz/upspin.io/$pkg/$name"
	if [[ -d "$src" ]]; then
		mkdir -p "$pkg/testdata/fuzz/$name"
		cp -n "$src"/* "$pkg/testdata/fuzz/$name/" 2>/dev/null || true
	fi
done <<<"$targets"
exit $status
