// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
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
	return journalState{
		nodes: map[fuse.NodeID]journalNode{
			1: {inode: 1, refs: 2, mode: uint32(os.ModeDir | 0o500)},
			2: {inode: 5, gen: 1, refs: 1, mode: 0o700, path: "u@x.com/b", mapped: true},
			3: {inode: 6, gen: 1, refs: 3, mode: 0o700, path: "u@x.com/c"},
		},
		handles: map[fuse.HandleID]journalHandle{1: {node: 2, flags: uint32(fuse.OpenReadWrite)}},
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
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if err := punchHole(f, journalHeaderSize, 0); err == nil && stat.Blocks*512 >= stat.Size {
		t.Logf("file of %d bytes uses %d blocks; holes may not be supported here", stat.Size, stat.Blocks)
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
