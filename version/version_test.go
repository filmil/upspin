// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"testing"
	"time"
)

// setVersion sets the stamped variables for one test and restores them.
func setVersion(t *testing.T, sha, release string, built time.Time) {
	t.Helper()
	oldSHA, oldRelease, oldTime := GitSHA, Release, BuildTime
	t.Cleanup(func() { GitSHA, Release, BuildTime = oldSHA, oldRelease, oldTime })
	GitSHA, Release, BuildTime = sha, release, built
}

func TestVersion(t *testing.T) {
	built := time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, sha, release string
		built              time.Time
		want               string
	}{
		{"unstamped", "", "", time.Time{}, "devel\n"},
		{"stamped", "4ae80a4", "", built,
			"Build time: Nov 20 06:00:00 2026 UTC\nGit hash:   4ae80a4\n"},
		{"release", "4ae80a4", "v46.2.0", built,
			"Release:    v46.2.0\nBuild time: Nov 20 06:00:00 2026 UTC\nGit hash:   4ae80a4\n"},
		{"no time", "4ae80a4", "", time.Time{}, "Git hash:   4ae80a4\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setVersion(t, tc.sha, tc.release, tc.built)
			if got := Version(); got != tc.want {
				t.Errorf("Version() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStamped(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "",
		"4ae80a4":              "4ae80a4",
		"{STABLE_GIT_COMMIT}":  "",
		"{STABLE_RELEASE_TAG}": "",
	} {
		if got := stamped(in); got != want {
			t.Errorf("stamped(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBuildTime(t *testing.T) {
	got := parseBuildTime("2026-11-20T07:00:00+01:00")
	if want := time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("parseBuildTime = %v, want %v", got, want)
	}
	if got := parseBuildTime("not a time"); !got.IsZero() {
		t.Errorf("parseBuildTime of a bad value = %v, want the zero time", got)
	}
	if got := parseBuildTime(""); !got.IsZero() {
		t.Errorf("parseBuildTime of nothing = %v, want the zero time", got)
	}
}
