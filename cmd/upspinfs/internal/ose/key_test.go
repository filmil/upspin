// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ose

import (
	"path/filepath"
	"testing"
)

// TestKeyReopensFile writes a file, forgets it as a new process would, and
// reads it back with the saved key.
func TestKeyReopensFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "f")
	f, err := Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("secret contents"), 0); err != nil {
		t.Fatal(err)
	}
	key, ok := Key(name)
	if !ok {
		t.Fatal("no key for an open file")
	}
	f.Close()
	state.Lock()
	delete(state.nameToFile, name)
	state.toRemove.Remove(name)
	state.Unlock()

	g, err := OpenFileWithKey(name, O_RDWR, 0600, key)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	buf := make([]byte, len("secret contents"))
	if _, err := g.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "secret contents" {
		t.Errorf("read %q with the saved key", buf)
	}
	if _, err := OpenFileWithKey(name, O_RDWR, 0600, key[:5]); err == nil {
		t.Error("OpenFileWithKey accepted a short key")
	}
	other := append([]byte(nil), key...)
	other[0] ^= 1
	if _, err := OpenFileWithKey(name, O_RDWR, 0600, other); err == nil {
		t.Error("OpenFileWithKey accepted another key for a known file")
	}
	if _, ok := Key(filepath.Join(t.TempDir(), "none")); ok {
		t.Error("Key returned a key for an unknown file")
	}
}
