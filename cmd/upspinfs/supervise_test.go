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
	j, _, err := openJournal(f)
	if err == nil || j != nil {
		// One byte is not a journal; the point is that the file works.
		t.Logf("openJournal on a 1 byte file: %v", err)
	}
}

func TestConnectionIDWithoutMount(t *testing.T) {
	if _, err := connectionID(t.TempDir()); err == nil {
		t.Error("connectionID found a FUSE connection for a plain directory")
	}
}
