// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"sort"
	"strings"
	"testing"
)

// listrefsLines returns the leading lines of stdout that have the three
// tab-separated fields of listrefs, split into fields. It stops at the
// first other line, so output of a later command (info) is ignored.
func listrefsLines(t *testing.T, cmd *cmdTest, stdout, stderr string) [][]string {
	t.Helper()
	if stderr != "" {
		t.Fatalf("%q: unexpected error:\n\t%q", cmd.name, stderr)
	}
	var out [][]string
	for _, line := range strings.Split(stdout, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == "" || f[1] == "" || f[2] == "" {
			break
		}
		out = append(out, f)
	}
	return out
}

// listrefsMatchInfo is a post function for "listrefs path" followed by
// "info path": every line of listrefs must name a block that info shows,
// with the reference and the endpoint in their columns, and there must be
// at least min of them.
func listrefsMatchInfo(min int) func(t *testing.T, r *runner, cmd *cmdTest, stdout, stderr string) {
	return func(t *testing.T, r *runner, cmd *cmdTest, stdout, stderr string) {
		lines := listrefsLines(t, cmd, stdout, stderr)
		if len(lines) < min {
			t.Fatalf("%q: %d lines, want at least %d:\n%s", cmd.name, len(lines), min, stdout)
		}
		blocks := strings.Count(stdout, "{") // One per block row of info.
		if len(lines) != blocks {
			t.Fatalf("%q: %d lines, but info shows %d blocks:\n%s", cmd.name, len(lines), blocks, stdout)
		}
		for _, f := range lines {
			// info prints a block's location as {endpoint reference}.
			if loc := "{" + f[1] + " " + f[0] + "}"; !strings.Contains(stdout, loc) {
				t.Fatalf("%q: %s not in info output:\n%s", cmd.name, loc, stdout)
			}
		}
	}
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
		listrefsMatchInfo(1),
	},
	{
		"listrefs large file setup",
		ann,
		do("put @/refs/large"),
		largeText,
		expectNoOutput(),
	},
	{
		"listrefs prints every block",
		ann,
		do(
			"listrefs @/refs/large",
			"info @/refs/large",
		),
		"",
		listrefsMatchInfo(2),
	},
	{
		"listrefs link named directly",
		ann,
		do("listrefs @/refs/link"),
		"",
		expectNoOutput(),
	},
	{
		"listrefs directory without -r",
		ann,
		do("listrefs @/refs"),
		"",
		fail("is a directory"),
	},
}
