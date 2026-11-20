#!/bin/bash
# Runs every fuzz target for a fixed time through Bazel's Go toolchain
# (Bazel itself does not drive the fuzz engine), then copies the corpus
# the engine grew into testdata/fuzz so that it can be committed.
#
# Arguments:
#   $1  fuzz time per target, in Go duration syntax, for example 60s.
#       Use 30s or more: the engine needs a few seconds to gather baseline
#       coverage and to stop its workers.
#
# Go 1.26 and earlier can fail a target that ran its whole time without
# finding anything, with only "context deadline exceeded"
# (https://github.com/golang/go/issues/75804). The fuzz coordinator compares
# the deadline error with the error of a child context, and the context
# package closes the parent's done channel before it cancels the child, so
# in that window the deadline counts as a failure. Such a run is counted as
# a pass, with a note, when the engine wrote no failing input. See
# spurious_deadline.
#
# Exit status:
#   0  every target ran to its time, or failed only by that deadline race
#   1  a target failed: a failing input (written under testdata/fuzz), a
#      panic, a fatal runtime error, a hang before fuzzing began, or a
#      build error
set -u

# package target pairs; keep in step with the Fuzz functions in the tree.
targets="
pack/ee FuzzUnmarshal
factotum FuzzParsePublicKey
factotum FuzzParseEncapsulationKey
factotum FuzzParsePrivateKey
factotum FuzzSecret2Archive
factotum FuzzKeyFileJSON
key/keygen FuzzSecretFromProquint
"

# spurious_deadline reports whether a failed fuzz run is only the Go
# coordinator's own deadline error (golang/go#75804).
#
# Arguments:
#   $1  file with the output of go test -fuzz
#   $2  number of files the run added to the package's testdata/fuzz/<target>
#
# It is true only when all of these hold:
#   - the run added no input to testdata/fuzz: a real crasher is written
#     there even when the race hides its message;
#   - the output names no failing input and shows no panic or fatal error;
#   - the engine finished its baseline and executed inputs, so a hang on a
#     seed input is not excused;
#   - exactly one target failed, and its only message is
#     "context deadline exceeded".
spurious_deadline() {
	local out=$1 added=$2
	[[ "$added" == 0 ]] || return 1
	grep -q -e 'Failing input written to' -e 'panic:' -e 'fatal error:' "$out" && return 1
	grep -q 'now fuzzing with' "$out" || return 1
	grep -q -E 'execs: [1-9][0-9]*' "$out" || return 1
	# Every line between "--- FAIL:" and the closing "FAIL" belongs to the
	# failure; the only one allowed is the deadline message.
	awk '
		/^--- FAIL:/ { fails++; inblock = 1; next }
		inblock && (/^FAIL/ || /^exit status/) { inblock = 0; next }
		inblock {
			line = $0; sub(/^[ \t]+/, "", line)
			if (line == "") next
			if (line == "context deadline exceeded") deadline++
			else other++
		}
		END { exit !(fails == 1 && deadline == 1 && other == 0) }
	' "$out"
}

# count_inputs prints the number of files in a directory, 0 if it is missing.
count_inputs() {
	if [[ -d "$1" ]]; then
		find "$1" -type f | wc -l
	else
		echo 0
	fi
}

main() {
	local fuzztime=${1:-60s}
	local gocache status=0
	# Paths below are relative to the repository root, where the go command
	# that bazel run starts works.
	cd "$(dirname "${BASH_SOURCE[0]}")/../.." || return 1
	gocache=$(bazel run @rules_go//go -- env GOCACHE 2>/dev/null | tail -1)
	# fuzz_out is global: the EXIT trap runs after main has returned.
	fuzz_out=$(mktemp)
	trap 'rm -f "$fuzz_out"' EXIT
	local out=$fuzz_out
	while read -r pkg name; do
		[[ -z "$pkg" ]] && continue
		echo "=== $pkg $name ($fuzztime)"
		local corpus="$pkg/testdata/fuzz/$name"
		local before
		before=$(count_inputs "$corpus")
		# pipefail makes the pipeline fail when go test fails, not only tee.
		if ! (set -o pipefail; bazel run @rules_go//go -- test -run='^$' -fuzz="^${name}\$" -fuzztime="$fuzztime" "./$pkg" 2>&1 | tee "$out"); then
			local added=$(($(count_inputs "$corpus") - before))
			if spurious_deadline "$out" "$added"; then
				echo "fuzz.sh: $name fuzzed and failed only with Go's own deadline error (golang/go#75804). Counted as a pass."
			else
				status=1
			fi
		fi
		# The engine keeps interesting inputs under GOCACHE; fold them into
		# the committed corpus so a later run starts from them.
		local src="$gocache/fuzz/upspin.io/$pkg/$name"
		if [[ -d "$src" ]]; then
			mkdir -p "$corpus"
			cp -n "$src"/* "$corpus/" 2>/dev/null || true
		fi
	done <<<"$targets"
	return $status
}

# The test sources this file for its functions; only a direct run fuzzes.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
	exit $?
fi
