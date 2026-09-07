// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package compat checks that the upspin binary built from this tree and
// one built from an older commit can read each other's files. It starts
// an Upspin cluster with upbox from this tree's binaries, then has the old
// client write a file that the new client reads, and the reverse.
//
// The test runs only when UPSPIN_COMPAT_OLD names the old upspin binary;
// .github/scripts/compat.sh builds that binary from the base of a pull
// request and sets the variable.
package compat

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"upspin.io/upbox"
)

const schemaYAML = `
users:
- name: compat@example.com
servers:
- name: keyserver
- name: storeserver
- name: dirserver
domain: example.com
`

func TestOldAndNewBinaries(t *testing.T) {
	old := os.Getenv("UPSPIN_COMPAT_OLD")
	if old == "" {
		t.Skip("set UPSPIN_COMPAT_OLD to the path of an older upspin binary")
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("old binary: %v", err)
	}
	sc, err := upbox.SchemaFromYAML(schemaYAML)
	if err != nil {
		t.Fatal(err)
	}
	sc.LogLevel = "error"
	if err := sc.Start(); err != nil {
		t.Fatal(err)
	}
	defer sc.Stop()
	newBin := sc.Command("upspin")
	cfg := "-config=" + sc.Config("compat@example.com")

	run := func(bin string, stdin []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(bin, append([]string{cfg, "-log=error"}, args...)...)
		cmd.Stdin = bytes.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", bin, args, err, stderr.String())
		}
		return out
	}

	// upbox registers the user; the root directory is the client's to make.
	run(newBin, nil, "mkdir", "compat@example.com/")

	// One direction, then the other, for a small file and one that spans
	// several blocks, all under the ee packing that both binaries share.
	cases := []struct {
		writer, reader, label string
	}{
		{old, newBin, "old writes, new reads"},
		{newBin, old, "new writes, old reads"},
	}
	texts := map[string][]byte{
		"small": []byte("compatibility across binaries"),
		"large": bytes.Repeat([]byte("0123456789abcdef"), 3*1024*1024/16+7),
	}
	for _, c := range cases {
		for size, text := range texts {
			name := fmt.Sprintf("compat@example.com/%s-%s", size, c.label[:3])
			run(c.writer, text, "put", name)
			got := run(c.reader, nil, "get", name)
			if !bytes.Equal(got, text) {
				t.Errorf("%s (%s): read %d bytes, want %d; content differs", c.label, size, len(got), len(text))
			}
			// The reader can also list and inspect what the writer stored.
			run(c.reader, nil, "info", name)
		}
	}
}
