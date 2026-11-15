// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"sort"
	"strings"
	"testing"
)

// listrefsLines checks that each line of stdout has three tab-separated
// fields and returns the lines split into fields.
func listrefsLines(t *testing.T, cmd *cmdTest, stdout, stderr string) [][]string {
	t.Helper()
	if stderr != "" {
		t.Fatalf("%q: unexpected error:\n\t%q", cmd.name, stderr)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == "" || f[1] == "" || f[2] == "" {
			t.Fatalf("%q: bad line %q", cmd.name, line)
		}
		out = append(out, f)
	}
	return out
}

var listrefsTests = []cmdTest{
	{
		"listrefs setup",
		ann,
		do(
			"mkdir @/refs",
			"mkdir @/refs/sub",
		),
		"",
		expectNoOutput(),
	},
	putFile(ann, "@/refs/a", "alpha"),
	putFile(ann, "@/refs/sub/b", "beta"),
	{
		"listrefs link",
		ann,
		do("link @/refs/a @/refs/link"),
		"",
		expectNoOutput(),
	},
	{
		"listrefs tree",
		ann,
		do("listrefs -r @/refs"),
		"",
		func(t *testing.T, r *runner, cmd *cmdTest, stdout, stderr string) {
			var names []string
			for _, f := range listrefsLines(t, cmd, stdout, stderr) {
				names = append(names, f[2])
			}
			sort.Strings(names)
			// One block each; the link has none.
			want := []string{"ann@example.com/refs/a", "ann@example.com/refs/sub/b"}
			if strings.Join(names, " ") != strings.Join(want, " ") {
				t.Fatalf("%q: names = %q, want %q", cmd.name, names, want)
			}
		},
	},
	{
		"listrefs matches info",
		ann,
		do(
			"listrefs @/refs/a",
			"info @/refs/a",
		),
		"",
		func(t *testing.T, r *runner, cmd *cmdTest, stdout, stderr string) {
			first, rest, _ := strings.Cut(stdout, "\n")
			f := listrefsLines(t, cmd, first, stderr)
			if !strings.Contains(rest, f[0][0]) {
				t.Fatalf("%q: reference %q not in info output:\n%s", cmd.name, f[0][0], rest)
			}
		},
	},
	{
		"listrefs directory without -r",
		ann,
		do("listrefs @/refs"),
		"",
		fail("is a directory"),
	},
}
