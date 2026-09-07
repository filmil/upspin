#!/usr/bin/env python3
"""Fail when a package's line coverage falls below its floor.

Reads the LCOV report that bazel coverage writes and compares the line
coverage of each package below with its floor. The floors are a ratchet:
they sit at the coverage each package had when the gate was added, and
must only go up. The target is 90 percent on every crypto package; see
TODO.filmil.md.

Arguments:
  argv[1]  path to the LCOV report (bazel-out/_coverage/_coverage_report.dat)

Exit status:
  0  every package meets its floor
  1  at least one package is below its floor, or is missing from the report
  2  the report cannot be read
"""
import collections
import sys

# package: minimum line coverage, in percent.
FLOORS = {
    "factotum": 80,
    "key/keygen": 35,
    "pack": 85,
    "pack/ee": 75,
    "pack/packutil": 80,
}


def coverage(path):
    """Return {package: (hit, total)} from an LCOV file."""
    cov = collections.defaultdict(lambda: [0, 0])
    current = None
    for line in open(path):
        line = line.strip()
        if line.startswith("SF:"):
            current = "/".join(line[3:].split("/")[:-1])
        elif line.startswith("DA:") and current:
            _, hits = line[3:].split(",")[:2]
            cov[current][0] += int(hits) > 0
            cov[current][1] += 1
    return cov


def main():
    if len(sys.argv) != 2:
        print("usage: coverage_gate.py <lcov report>", file=sys.stderr)
        return 2
    try:
        cov = coverage(sys.argv[1])
    except OSError as e:
        print(f"coverage_gate: {e}", file=sys.stderr)
        return 2
    status = 0
    for pkg, floor in sorted(FLOORS.items()):
        if pkg not in cov:
            print(f"coverage_gate: {pkg}: not in the report", file=sys.stderr)
            status = 1
            continue
        hit, total = cov[pkg]
        pct = 100.0 * hit / total if total else 0.0
        verdict = "ok" if pct >= floor else "BELOW FLOOR"
        print(f"{pct:6.1f}% (floor {floor}%) {hit}/{total} {pkg} {verdict}")
        if pct < floor:
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
