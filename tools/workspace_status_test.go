// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tools_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// script is the workspace status command, from the test's runfiles.
const script = "workspace_status.sh"

// run runs the script in dir with the given PATH, and returns its keys.
func run(t *testing.T, dir, path string) map[string]string {
	t.Helper()
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", abs)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + path,
		"HOME=" + t.TempDir(),
		"GIT_CEILING_DIRECTORIES=" + filepath.Dir(dir),
		"GIT_CONFIG_NOSYSTEM=1",
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v", script, err)
	}
	keys := map[string]string{}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	for _, l := range lines {
		k, v, ok := strings.Cut(l, " ")
		if !ok {
			t.Fatalf("line %q is not KEY VALUE; output:\n%s", l, out)
		}
		keys[k] = v
	}
	want := []string{"STABLE_GIT_COMMIT", "STABLE_BUILD_TIME", "STABLE_RELEASE_TAG", "GIT_STATUS"}
	if len(lines) != len(want) {
		t.Fatalf("%d lines, want %d; output:\n%s", len(lines), len(want), out)
	}
	for _, k := range want {
		if _, ok := keys[k]; !ok {
			t.Fatalf("no key %s; output:\n%s", k, out)
		}
	}
	return keys
}

// repo makes a git repository with one commit holding the given files.
func repo(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "first")
	return dir
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// systemPath is the PATH the script runs with: wherever git is found.
func systemPath(t *testing.T) string {
	t.Helper()
	g, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	return filepath.Dir(g) + ":/usr/bin:/bin"
}

// fakeGit puts a git in front of the real one that runs body for status.
func fakeGit(t *testing.T, body string) string {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	wrapper := "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = status ]; then " + body + "; fi; done\nexec " + real + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(wrapper), 0755); err != nil {
		t.Fatal(err)
	}
	return dir + ":" + systemPath(t)
}

func TestClean(t *testing.T) {
	dir := repo(t, "a")
	k := run(t, dir, systemPath(t))
	if want := git(t, dir, "rev-parse", "HEAD"); k["STABLE_GIT_COMMIT"] != want {
		t.Errorf("STABLE_GIT_COMMIT = %q, want %q", k["STABLE_GIT_COMMIT"], want)
	}
	if k["GIT_STATUS"] != "" || k["STABLE_BUILD_TIME"] == "" {
		t.Errorf("clean tree: %v", k)
	}
}

func TestTag(t *testing.T) {
	dir := repo(t, "a")
	git(t, dir, "tag", "v1.2.3")
	if k := run(t, dir, systemPath(t)); k["STABLE_RELEASE_TAG"] != "v1.2.3" {
		t.Errorf("STABLE_RELEASE_TAG = %q, want v1.2.3", k["STABLE_RELEASE_TAG"])
	}
}

func TestDirty(t *testing.T) {
	dir := repo(t, "a", "b")
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("changed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	k := run(t, dir, systemPath(t))
	if !strings.HasSuffix(k["STABLE_GIT_COMMIT"], "-dirty") || !strings.Contains(k["GIT_STATUS"], "M a") {
		t.Errorf("a modified file: %v", k)
	}

	// A staged change, and a second file, on one line.
	if err := os.WriteFile(filepath.Join(dir, "b"), []byte("changed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "b")
	k = run(t, dir, systemPath(t))
	if !strings.Contains(k["GIT_STATUS"], "M  b") || !strings.Contains(k["GIT_STATUS"], ";") {
		t.Errorf("a staged and a modified file: %v", k)
	}
}

func TestUntrackedIsClean(t *testing.T) {
	dir := repo(t, "a")
	if err := os.WriteFile(filepath.Join(dir, "new"), []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if k := run(t, dir, systemPath(t)); strings.HasSuffix(k["STABLE_GIT_COMMIT"], "-dirty") {
		t.Errorf("an untracked file made the tree dirty: %v", k)
	}
}

// TestOddFileName changes a file whose name git status escapes; the output
// stays one KEY VALUE per line (run checks that).
func TestOddFileName(t *testing.T) {
	name := "tab\tand\\back;slash"
	dir := repo(t, name)
	if err := os.WriteFile(filepath.Join(dir, name), []byte("changed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if k := run(t, dir, systemPath(t)); !strings.HasSuffix(k["STABLE_GIT_COMMIT"], "-dirty") {
		t.Errorf("an odd file name: %v", k)
	}
}

func TestWarningOnCleanTree(t *testing.T) {
	dir := repo(t, "a")
	k := run(t, dir, fakeGit(t, "echo 'warning: something odd' >&2"))
	if strings.HasSuffix(k["STABLE_GIT_COMMIT"], "-dirty") || k["GIT_STATUS"] != "" {
		t.Errorf("a warning on stderr made a clean tree dirty: %v", k)
	}
}

func TestStatusFails(t *testing.T) {
	dir := repo(t, "a")
	k := run(t, dir, fakeGit(t, "echo 'fatal: index broken' >&2; exit 128"))
	if !strings.HasSuffix(k["STABLE_GIT_COMMIT"], "-dirty") || !strings.Contains(k["GIT_STATUS"], "git status failed: fatal: index broken") {
		t.Errorf("git status failing: %v", k)
	}
}

func TestOutsideGit(t *testing.T) {
	k := run(t, t.TempDir(), systemPath(t))
	for key, v := range k {
		if v != "" {
			t.Errorf("outside git: %s = %q, want empty", key, v)
		}
	}
}
