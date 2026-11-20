#!/bin/bash
# Tests spurious_deadline in fuzz.sh against outputs of go test -fuzz: the
# race of https://github.com/golang/go/issues/75804 must pass, and every
# real failure must still fail. CI runs it before the fuzz job.
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=fuzz.sh
source "$here/fuzz.sh"

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
failures=0

# check NAME WANT ADDED: WANT is "spurious" or "real"; the output is on stdin.
check() {
	local name=$1 want=$2 added=$3 got=real
	cat >"$dir/out"
	if spurious_deadline "$dir/out" "$added"; then
		got=spurious
	fi
	if [[ "$got" != "$want" ]]; then
		echo "FAIL: $name: got $got, want $want"
		failures=$((failures + 1))
	else
		echo "ok: $name"
	fi
}

# From https://github.com/filmil/upspin/actions/runs/44474215287.
check "the race, as seen in CI" spurious 0 <<'EOF'
fuzz: elapsed: 57s, execs: 1171193 (19123/sec), new interesting: 22 (total: 379)
fuzz: elapsed: 1m1s, execs: 1171193 (0/sec), new interesting: 22 (total: 379)
--- FAIL: FuzzSecret2Archive (61.04s)
    context deadline exceeded
FAIL
exit status 1
FAIL	upspin.io/factotum	61.056s
EOF

check "a crasher" real 1 <<'EOF'
fuzz: elapsed: 3s, execs: 1000 (333/sec), new interesting: 1 (total: 10)
--- FAIL: FuzzSecret2Archive (3.10s)
    --- FAIL: FuzzSecret2Archive (0.00s)
        factotum_test.go:460: archive lost a key

    Failing input written to testdata/fuzz/FuzzSecret2Archive/0123abcd
    To re-run:
    go test -run=FuzzSecret2Archive/0123abcd
FAIL
EOF

check "a crasher whose message the race hid" real 1 <<'EOF'
fuzz: elapsed: 1m0s, execs: 900000 (0/sec), new interesting: 3 (total: 40)
--- FAIL: FuzzParsePublicKey (61.02s)
    context deadline exceeded
FAIL
EOF

check "a panic" real 0 <<'EOF'
--- FAIL: FuzzUnmarshal (2.00s)
    context deadline exceeded
panic: runtime error: index out of range [3] with length 3
FAIL
EOF

check "another error" real 0 <<'EOF'
--- FAIL: FuzzUnmarshal (0.50s)
    fuzzing process hung or terminated unexpectedly: exit status 2
FAIL
EOF

check "two failing targets" real 0 <<'EOF'
--- FAIL: FuzzA (61.00s)
    context deadline exceeded
--- FAIL: FuzzB (61.00s)
    context deadline exceeded
FAIL
EOF

check "no failure line" real 0 <<'EOF'
build failed: undefined: foo
EOF

if [[ $failures != 0 ]]; then
	echo "$failures failed"
	exit 1
fi
echo "all passed"
