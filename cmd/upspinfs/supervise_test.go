// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"reflect"
	"testing"

	"upspin.io/third_party/fuse"
)

func TestArgsWithout(t *testing.T) {
	in := []string{"-supervise", "-config=c", "--supervise=true", "-supervisex", "-log", "info", "--", "-supervise"}
	want := []string{"-config=c", "-supervisex", "-log", "info", "--", "-supervise"}
	if got := argsWithout(in, "supervise"); !reflect.DeepEqual(got, want) {
		t.Errorf("argsWithout = %q, want %q", got, want)
	}
}

func TestChildFlags(t *testing.T) {
	got := childFlags(fuse.Protocol{Major: 7, Minor: 12}, true)
	want := []string{"-fuse_fd=3", "-fuse_proto=7.12", "-journal_fd=4"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("childFlags = %q, want %q", got, want)
	}
	if got := childFlags(fuse.Protocol{Major: 7, Minor: 12}, false); len(got) != 2 {
		t.Errorf("childFlags without a journal = %q", got)
	}
}

func TestMemFile(t *testing.T) {
	f, err := memFile("test")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, 0); err != nil || buf[0] != 'x' {
		t.Errorf("read back %q, %v", buf, err)
	}
	if _, _, err := openJournal(f); err == nil {
		t.Error("openJournal accepted one byte as a journal")
	}
}

func TestMountMinor(t *testing.T) {
	const info = `22 1 0:21 / /proc rw - proc proc rw
290 30 0:290 / /tmp/a\040b rw - fuse.upspin upspin rw
291 30 0:41 / /tmp/c rw - fuse.upspin upspin rw
292 291 0:77 / /tmp/c rw - fuse.upspin upspin rw
`
	tests := map[string]string{
		"/tmp/a b": "290",
		"/tmp/c":   "77", // The upper of two stacked mounts.
		"/tmp/d":   "",
	}
	for mp, want := range tests {
		if got := mountMinor(info, mp); got != want {
			t.Errorf("mountMinor(%q) = %q, want %q", mp, got, want)
		}
	}
}

func TestConnectionIDWithoutMount(t *testing.T) {
	if _, err := connectionID(t.TempDir()); err == nil {
		t.Error("connectionID found a FUSE connection for a plain directory")
	}
}
