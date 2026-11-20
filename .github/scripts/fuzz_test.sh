#!/bin/bash
# Tests fuzz.sh: spurious_deadline against outputs of go test -fuzz, and
# main end to end with a stand-in for bazel. The race of
# https://github.com/golang/go/issues/75804 must pass, and every real
# failure must still fail. CI runs it before the fuzz job.
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
check "the race, as seen in CI" spurious 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 379/379 completed, now fuzzing with 4 workers
fuzz: elapsed: 57s, execs: 1171193 (19123/sec), new interesting: 22 (total: 379)
fuzz: elapsed: 1m1s, execs: 1171193 (0/sec), new interesting: 22 (total: 379)
--- FAIL: FuzzSecret2Archive (61.04s)
    context deadline exceeded
FAIL
exit status 1
FAIL	upspin.io/factotum	61.056s
OUT

check "a crasher" real 1 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 3s, execs: 1000 (333/sec), new interesting: 1 (total: 10)
--- FAIL: FuzzSecret2Archive (3.10s)
    --- FAIL: FuzzSecret2Archive (0.00s)
        factotum_test.go:460: archive lost a key

    Failing input written to testdata/fuzz/FuzzSecret2Archive/0123abcd
    To re-run:
    go test -run=FuzzSecret2Archive/0123abcd
FAIL
OUT

check "a crasher whose message the race hid" real 1 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 1m0s, execs: 900000 (0/sec), new interesting: 3 (total: 40)
--- FAIL: FuzzParsePublicKey (61.02s)
    context deadline exceeded
FAIL
OUT

check "a panic" real 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 2s, execs: 900 (450/sec), new interesting: 0 (total: 9)
--- FAIL: FuzzUnmarshal (2.00s)
    context deadline exceeded
panic: runtime error: index out of range [3] with length 3
FAIL
OUT

check "an indented panic" real 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 1m0s, execs: 5000 (0/sec), new interesting: 0 (total: 9)
--- FAIL: FuzzUnmarshal (61.00s)
    context deadline exceeded
        panic: assignment to entry in nil map
FAIL
OUT

check "a fatal runtime error" real 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 1m0s, execs: 5000 (0/sec), new interesting: 0 (total: 9)
fatal error: concurrent map writes
--- FAIL: FuzzUnmarshal (61.00s)
    context deadline exceeded
FAIL
OUT

check "another error" real 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 1s, execs: 50 (50/sec), new interesting: 0 (total: 9)
--- FAIL: FuzzUnmarshal (0.50s)
    fuzzing process hung or terminated unexpectedly: exit status 2
FAIL
OUT

check "another message after the deadline" real 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 1m0s, execs: 5000 (0/sec), new interesting: 0 (total: 9)
--- FAIL: FuzzUnmarshal (61.00s)
    context deadline exceeded
    packdata_test.go:400: cleanup failed
FAIL
OUT

check "two failing targets" real 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 1m0s, execs: 5000 (0/sec), new interesting: 0 (total: 9)
--- FAIL: FuzzA (61.00s)
    context deadline exceeded
--- FAIL: FuzzB (61.00s)
    context deadline exceeded
FAIL
OUT

check "a hang before fuzzing began" real 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 0/379 completed
--- FAIL: FuzzSecret2Archive (61.00s)
    context deadline exceeded
FAIL
OUT

check "a failure line at the end" real 0 <<'OUT'
fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers
fuzz: elapsed: 1m0s, execs: 5000 (0/sec), new interesting: 0 (total: 9)
--- FAIL: FuzzUnmarshal (61.00s)
OUT

check "no failure line" real 0 <<'OUT'
build failed: undefined: foo
OUT

# main, end to end, with a stand-in for "bazel run @rules_go//go --": one
# target hits the race and the rest pass, so fuzz.sh must exit 0. That also
# checks that it cleans up after itself under set -u. MODE=crash makes the
# racing target report a failing input instead, which must fail.
stub=$dir/bin
mkdir -p "$stub"
cat >"$stub/bazel" <<'STUB'
#!/bin/bash
case "$*" in
*"env GOCACHE"*) echo /nonexistent/gocache ;;
*FuzzSecret2Archive*)
	echo "fuzz: elapsed: 0s, gathering baseline coverage: 9/9 completed, now fuzzing with 4 workers"
	echo "fuzz: elapsed: 1m0s, execs: 5000 (0/sec), new interesting: 0 (total: 9)"
	echo "--- FAIL: FuzzSecret2Archive (61.00s)"
	echo "    context deadline exceeded"
	if [[ "${MODE:-}" == crash ]]; then
		echo "    Failing input written to testdata/fuzz/FuzzSecret2Archive/0123abcd"
	fi
	echo "FAIL"
	exit 1 ;;
*) echo "ok	upspin.io/x	60.1s" ;;
esac
STUB
chmod +x "$stub/bazel"

if PATH="$stub:$PATH" bash "$here/fuzz.sh" 1s >"$dir/main.out" 2>&1 && ! grep -q 'unbound variable' "$dir/main.out"; then
	echo "ok: main counts the race as a pass, without shell errors"
else
	echo "FAIL: main failed or printed a shell error on the race:"
	cat "$dir/main.out"
	failures=$((failures + 1))
fi
if MODE=crash PATH="$stub:$PATH" bash "$here/fuzz.sh" 1s >"$dir/main.out" 2>&1; then
	echo "FAIL: main passed a run with a failing input"
	failures=$((failures + 1))
else
	echo "ok: main fails a run with a failing input"
fi

if [[ $failures != 0 ]]; then
	echo "$failures failed"
	exit 1
fi
echo "all passed"
