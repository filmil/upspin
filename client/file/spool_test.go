// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// setMaxInMemory lowers the spill threshold for the duration of a test.
func setMaxInMemory(t *testing.T, n int64) {
	t.Helper()
	old := maxInMemory
	maxInMemory = n
	t.Cleanup(func() { maxInMemory = old })
}

// writeInto applies the write of b at off to want, the expected contents,
// extending it with zeros as necessary, just as a spool should.
func writeInto(want []byte, b []byte, off int64) []byte {
	if end := off + int64(len(b)); end > int64(len(want)) {
		want = append(want, make([]byte, end-int64(len(want)))...)
	}
	copy(want[off:], b)
	return want
}

// pattern returns n bytes with each byte equal to its offset plus seed.
func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i) + seed
	}
	return b
}

func checkContents(t *testing.T, s *spool, want []byte) {
	t.Helper()
	if s.size != int64(len(want)) {
		t.Fatalf("size = %d, want %d", s.size, len(want))
	}
	got, err := io.ReadAll(s.reader())
	if err != nil {
		t.Fatal("reading spool:", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("contents differ: got %d bytes %q, want %d bytes %q", len(got), got, len(want), want)
	}
}

func TestSpoolInMemory(t *testing.T) {
	setMaxInMemory(t, 64)
	var s spool
	var want []byte

	// Sequential writes, an overwrite and a write past the end,
	// all within the in-memory limit.
	for _, w := range []struct {
		b   []byte
		off int64
	}{
		{pattern(10, 0), 0},
		{pattern(10, 10), 10},
		{pattern(5, 100), 3},
		{pattern(4, 200), 30}, // Leaves a hole of zeros at 20-30.
		{nil, 40},             // An empty write beyond the end extends with zeros.
	} {
		n, err := s.writeAt(w.b, w.off)
		if err != nil {
			t.Fatalf("writeAt(%d bytes, %d): %v", len(w.b), w.off, err)
		}
		if n != len(w.b) {
			t.Fatalf("writeAt(%d bytes, %d) wrote %d", len(w.b), w.off, n)
		}
		want = writeInto(want, w.b, w.off)
		checkContents(t, &s, want)
	}
	if s.file != nil {
		t.Fatal("spool spilled to disk below maxInMemory")
	}
	if err := s.close(); err != nil {
		t.Fatal("close:", err)
	}
	if s.mem != nil {
		t.Fatal("close did not release memory")
	}
}

func TestSpoolSpillsToDisk(t *testing.T) {
	setMaxInMemory(t, 64)
	var s spool
	var want []byte

	// Fill exactly to the limit; still in memory.
	b := pattern(64, 0)
	if _, err := s.writeAt(b, 0); err != nil {
		t.Fatal(err)
	}
	want = writeInto(want, b, 0)
	if s.file != nil {
		t.Fatal("spool spilled to disk at exactly maxInMemory")
	}
	checkContents(t, &s, want)

	// One more byte spills to disk, preserving what was in memory.
	b = pattern(1, 50)
	if _, err := s.writeAt(b, 64); err != nil {
		t.Fatal(err)
	}
	want = writeInto(want, b, 64)
	if s.file == nil {
		t.Fatal("spool did not spill to disk beyond maxInMemory")
	}
	if s.mem != nil {
		t.Fatal("spool kept memory after spilling")
	}
	tmp := s.file.Name()
	if _, err := os.Stat(tmp); err != nil {
		t.Fatalf("temporary file %q: %v", tmp, err)
	}
	checkContents(t, &s, want)

	// Overwrites and holes work on disk too.
	for _, w := range []struct {
		b   []byte
		off int64
	}{
		{pattern(100, 7), 65},
		{pattern(20, 99), 10},
		{pattern(3, 1), 300}, // Leaves a hole of zeros.
		{nil, 320},           // An empty write beyond the end extends with zeros.
		{nil, 100},           // An empty write within the contents changes nothing.
	} {
		n, err := s.writeAt(w.b, w.off)
		if err != nil {
			t.Fatalf("writeAt(%d bytes, %d): %v", len(w.b), w.off, err)
		}
		if n != len(w.b) {
			t.Fatalf("writeAt(%d bytes, %d) wrote %d", len(w.b), w.off, n)
		}
		want = writeInto(want, w.b, w.off)
		checkContents(t, &s, want)
	}

	// Close removes the temporary file.
	if err := s.close(); err != nil {
		t.Fatal("close:", err)
	}
	if s.file != nil {
		t.Fatal("close did not release the file")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("temporary file %q not removed on close: %v", tmp, err)
	}
}

func TestSpoolEmpty(t *testing.T) {
	var s spool
	checkContents(t, &s, nil)
	if err := s.close(); err != nil {
		t.Fatal("close:", err)
	}
}

// TestFileSpillsToDisk checks that a File written beyond the in-memory
// limit is stored in full on Close, and leaves no temporary file behind.
func TestFileSpillsToDisk(t *testing.T) {
	setMaxInMemory(t, 16)
	f := create(fileName)
	var want []byte

	// Write sequentially past the limit, then go back and overwrite.
	for i := 0; i < 10; i++ {
		b := pattern(7, byte(i*7))
		n, err := f.Write(b)
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if n != len(b) {
			t.Fatalf("write %d: wrote %d bytes, want %d", i, n, len(b))
		}
		want = writeInto(want, b, int64(i*7))
	}
	b := pattern(5, 200)
	if _, err := f.WriteAt(b, 3); err != nil {
		t.Fatal("writeAt:", err)
	}
	want = writeInto(want, b, 3)

	realFile := f.(*File)
	if realFile.spool.file == nil {
		t.Fatal("file did not spill to disk")
	}
	tmp := realFile.spool.file.Name()

	// Seek relative to the end reports the full size.
	end, err := f.Seek(0, 2)
	if err != nil {
		t.Fatal("seek:", err)
	}
	if end != int64(len(want)) {
		t.Fatalf("seek to end = %d, want %d", end, len(want))
	}

	if err := f.Close(); err != nil {
		t.Fatal("close:", err)
	}
	dummy := realFile.client.(*dummyClient)
	if !bytes.Equal(dummy.putData, want) {
		t.Fatalf("put %d bytes %q, want %d bytes %q", len(dummy.putData), dummy.putData, len(want), want)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("temporary file %q not removed on close: %v", tmp, err)
	}
}
