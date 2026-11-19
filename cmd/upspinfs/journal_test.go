// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"upspin.io/third_party/fuse"
)

func tempJournal(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func mustOpenJournal(t *testing.T, f *os.File) (*journal, journalState) {
	t.Helper()
	j, st, err := openJournal(f)
	if err != nil {
		t.Fatal(err)
	}
	return j, st
}

func checkState(t *testing.T, got, want journalState) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("journal state:\n got %+v\nwant %+v", got, want)
	}
}

// writeSample records a sequence of changes and returns the state they leave.
func writeSample(j *journal) journalState {
	j.putNode(1, journalNode{inode: 1, refs: 2, mode: uint32(os.ModeDir | 0o500)})
	j.putNode(2, journalNode{inode: 5, gen: 1, refs: 1, mode: 0o700, path: "u@x.com/a", mapped: true})
	j.putNode(3, journalNode{inode: 6, gen: 1, refs: 3, mode: 0o700, path: "u@x.com/c", mapped: true})
	j.putNode(4, journalNode{inode: 7, gen: 9, refs: 1, path: "u@x.com/gone", mapped: true})
	j.forgetNode(4)
	j.setPath(2, "u@x.com/b")
	j.setMapped(3, false)
	j.putHandle(1, journalHandle{node: 2, flags: uint32(fuse.OpenReadWrite)})
	j.putHandle(2, journalHandle{node: 3})
	j.releaseHandle(2)
	j.setPath(99, "ignored, no such node")
	j.putCache(2, journalCache{seq: -1, fname: "/c/tmp/7", key: []byte("0123456789abcdef0123456789abcdef")})
	j.putCache(3, journalCache{seq: 4, fname: "/c/tmp/8", key: []byte("k")})
	j.dropCache(3)
	j.putCache(4, journalCache{seq: 1, fname: "/c/tmp/9"}) // Node 4 is forgotten.
	return journalState{
		nodes: map[fuse.NodeID]journalNode{
			1: {inode: 1, refs: 2, mode: uint32(os.ModeDir | 0o500)},
			2: {inode: 5, gen: 1, refs: 1, mode: 0o700, path: "u@x.com/b", mapped: true},
			3: {inode: 6, gen: 1, refs: 3, mode: 0o700, path: "u@x.com/c"},
		},
		handles: map[fuse.HandleID]journalHandle{1: {node: 2, flags: uint32(fuse.OpenReadWrite)}},
		caches:  map[fuse.NodeID]journalCache{2: {seq: -1, fname: "/c/tmp/7", key: []byte("0123456789abcdef0123456789abcdef")}},
		maxGen:  9,
	}
}

func TestJournalReplay(t *testing.T) {
	f := tempJournal(t)
	j, st := mustOpenJournal(t, f)
	checkState(t, st, newJournalState())
	want := writeSample(j)
	if j.err != nil {
		t.Fatal(j.err)
	}
	checkState(t, j.copyState(), want)

	_, st = mustOpenJournal(t, f)
	checkState(t, st, want)
}

func TestJournalDropsDamagedTail(t *testing.T) {
	f := tempJournal(t)
	j, _ := mustOpenJournal(t, f)
	want := writeSample(j)
	good := j.end

	// A record whose header promises more bytes than were written.
	if _, err := f.WriteAt([]byte{100, 0, 0, 0, 1, 2, 3, 4, recForget, 2}, good); err != nil {
		t.Fatal(err)
	}
	j, st := mustOpenJournal(t, f)
	checkState(t, st, want)
	if info, err := f.Stat(); err != nil || info.Size() != good {
		t.Errorf("file size after replay = %v (%v), want %d", info.Size(), err, good)
	}

	// The journal continues after the last good record.
	j.forgetNode(3)
	delete(want.nodes, 3)
	_, st = mustOpenJournal(t, f)
	checkState(t, st, want)
}

func TestJournalStopsAtBadChecksum(t *testing.T) {
	f := tempJournal(t)
	j, _ := mustOpenJournal(t, f)
	j.putNode(2, journalNode{inode: 5, refs: 1, path: "u@x.com/a", mapped: true})
	second := j.end
	j.putNode(3, journalNode{inode: 6, refs: 1, path: "u@x.com/b", mapped: true})

	// Damage the payload of the second record.
	if _, err := f.WriteAt([]byte{0xff}, second+9); err != nil {
		t.Fatal(err)
	}
	_, st := mustOpenJournal(t, f)
	want := newJournalState()
	want.nodes[2] = journalNode{inode: 5, refs: 1, path: "u@x.com/a", mapped: true}
	checkState(t, st, want)
}

func TestJournalRejectsBadHeader(t *testing.T) {
	f := tempJournal(t)
	if _, err := f.WriteAt([]byte("not a journal at all"), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openJournal(f); err == nil {
		t.Error("openJournal accepted a file without the magic string")
	}
}

func TestJournalCompacts(t *testing.T) {
	f := tempJournal(t)
	j, _ := mustOpenJournal(t, f)
	want := writeSample(j)
	for i := 0; i < 20000; i++ {
		j.putNode(2, journalNode{inode: 5, gen: 1, refs: uint64(i + 1), mode: 0o700, path: "u@x.com/b", mapped: true})
	}
	n := want.nodes[2]
	n.refs = 20000
	want.nodes[2] = n
	if j.err != nil {
		t.Fatal(j.err)
	}
	if j.start == journalHeaderSize {
		t.Fatal("the journal never compacted")
	}
	if j.records > compactFactor*compactMinRecords {
		t.Errorf("%d records after compaction", j.records)
	}
	_, st := mustOpenJournal(t, f)
	checkState(t, st, want)

	// The old records no longer take space, where the file system can
	// punch holes.
	if !canPunchHoles(t) {
		t.Skip("this file system cannot punch holes")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Blocks*512 >= stat.Size/2 {
		t.Errorf("journal of %d bytes uses %d bytes on disk; the old records were not freed", stat.Size, stat.Blocks*512)
	}
}

// canPunchHoles reports whether punchHole frees space in the test directory.
func canPunchHoles(t *testing.T) bool {
	f := tempJournal(t)
	if _, err := f.WriteAt(make([]byte, 1<<20), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := punchHole(f, 0, 1<<20); err != nil {
		return false
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	return stat.Blocks*512 < 1<<19
}

func TestJournalRejectsBadStart(t *testing.T) {
	for _, start := range []uint64{0, journalHeaderSize - 1, 1 << 40} {
		f := tempJournal(t)
		hdr := make([]byte, journalHeaderSize)
		copy(hdr, journalMagic)
		binary.LittleEndian.PutUint64(hdr[journalStartOff:], start)
		if _, err := f.WriteAt(hdr, 0); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openJournal(f); err == nil {
			t.Errorf("openJournal accepted start offset %d", start)
		}
	}
}

func TestJournalRejectsShortHeader(t *testing.T) {
	f := tempJournal(t)
	if _, err := f.WriteAt([]byte(journalMagic), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openJournal(f); err == nil {
		t.Error("openJournal accepted a header without a start offset")
	}
}

func TestApplyRecordRejectsDamage(t *testing.T) {
	good := encodeNode(2, journalNode{inode: 5, refs: 1, path: "u@x.com/a"})
	tests := map[string][]byte{
		"empty":          {},
		"unknown type":   {99, 1},
		"trailing bytes": append(append([]byte(nil), good...), 0),
		"short number":   {recForget, 0x80},
		"short string":   good[:len(good)-1],
	}
	for name, payload := range tests {
		st := newJournalState()
		if err := applyRecord(&st, payload); err == nil {
			t.Errorf("%s: applyRecord accepted the record", name)
		}
		if !reflect.DeepEqual(st, newJournalState()) {
			t.Errorf("%s: a rejected record changed the state to %+v", name, st)
		}
	}
}

func TestJournalRefusesHugeRecord(t *testing.T) {
	j, _ := mustOpenJournal(t, tempJournal(t))
	j.setPath(1, string(make([]byte, maxRecordSize)))
	if j.err == nil {
		t.Error("the journal wrote a record that replay would reject")
	}
}

// TestJournalStopsAfterWriteError checks that no record is written after a
// failed one, so that replay never skips a gap.
func TestJournalStopsAfterWriteError(t *testing.T) {
	f := tempJournal(t)
	j, _ := mustOpenJournal(t, f)
	j.putNode(2, journalNode{inode: 5, refs: 1})
	end := j.end
	j.fail(errors.New("injected"))
	j.putNode(3, journalNode{inode: 6, refs: 1})
	if j.end != end {
		t.Error("the journal wrote after an error")
	}
}

// TestJournalCrashDuringCompaction replays a journal whose snapshot was
// written but whose header still points at the old records.
func TestJournalCrashDuringCompaction(t *testing.T) {
	f := tempJournal(t)
	j, _ := mustOpenJournal(t, f)
	want := writeSample(j)
	j.writeSnapshot()
	if j.err != nil {
		t.Fatal(j.err)
	}
	_, st := mustOpenJournal(t, f)
	checkState(t, st, want)

	j, _ = mustOpenJournal(t, f)
	j.switchStart(j.writeSnapshot())
	_, st = mustOpenJournal(t, f)
	checkState(t, st, want)
}

func TestJournalWriteErrorIsKept(t *testing.T) {
	f := tempJournal(t)
	j, _ := mustOpenJournal(t, f)
	f.Close()
	j.putNode(2, journalNode{inode: 5, refs: 1})
	if j.err == nil {
		t.Error("a write to a closed file did not set the error")
	}
}

// TestRemoveAllExcept checks that a restart keeps exactly the cache files in
// use and that new temporary files do not reuse their names.
func TestRemoveAllExcept(t *testing.T) {
	dir := t.TempDir()
	c := newCache(testConfig.cfg, dir, maxBytes)
	keep := filepath.Join(dir, "tmp", "7")
	for _, name := range []string{keep, filepath.Join(dir, "tmp", "3"), filepath.Join(dir, "ab", "abcdef")} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c.removeAllExcept(map[string]bool{keep: true})
	var left []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			left = append(left, p)
		}
		return nil
	})
	if !reflect.DeepEqual(left, []string{keep}) {
		t.Errorf("files left: %v, want only %s", left, keep)
	}
	if got := c.mkTemp(); got == keep || got != filepath.Join(dir, "tmp", "8") {
		t.Errorf("next temporary file %s, want %s", got, filepath.Join(dir, "tmp", "8"))
	}
}
