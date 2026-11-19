// SPDX-License-Identifier: Apache-2.0

package fs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"upspin.io/third_party/fuse"
)

type testNode struct{ name string }

func (*testNode) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = 0o600
	return nil
}

type testHandle struct{ name string }

// recorder is a TableObserver that writes down what it is told.
type recorder struct{ events []string }

func (r *recorder) NodeSaved(e NodeEntry) {
	r.events = append(r.events, fmt.Sprintf("node %d inode=%d gen=%d refs=%d %s",
		e.ID, e.Inode, e.Generation, e.Refs, e.Node.(*testNode).name))
}

func (r *recorder) NodeRemoved(id fuse.NodeID) {
	r.events = append(r.events, fmt.Sprintf("forget %d", id))
}

func (r *recorder) HandleSaved(e HandleEntry) {
	r.events = append(r.events, fmt.Sprintf("handle %d %s", e.ID, e.Handle.(*testHandle).name))
}

func (r *recorder) HandleRemoved(id fuse.HandleID) {
	r.events = append(r.events, fmt.Sprintf("release %d", id))
}

func TestObserverSeesEveryChange(t *testing.T) {
	rec := &recorder{}
	s := New(nil, &Config{Observer: rec})
	if err := s.initTables(&testNode{"root"}); err != nil {
		t.Fatal(err)
	}

	a, b := &testNode{"a"}, &testNode{"b"}
	s.saveNode(10, a)
	s.saveNode(10, a)
	s.saveNode(11, b)
	s.dropNode(2, 1)
	s.dropNode(2, 1)
	s.saveNode(12, &testNode{"c"}) // Reuses ID 2 with a new generation.
	h := s.saveHandle(&testHandle{"h"})
	s.dropHandle(h)

	want := []string{
		"node 2 inode=10 gen=0 refs=1 a",
		"node 2 inode=10 gen=0 refs=2 a",
		"node 3 inode=11 gen=0 refs=1 b",
		"node 2 inode=10 gen=0 refs=1 a",
		"forget 2",
		"node 2 inode=12 gen=1 refs=1 c",
		"handle 1 h",
		"release 1",
	}
	if !reflect.DeepEqual(rec.events, want) {
		t.Errorf("events:\n got %q\nwant %q", rec.events, want)
	}
}

func TestRestoreKeepsIDs(t *testing.T) {
	root, a, b := &testNode{"root"}, &testNode{"a"}, &testNode{"b"}
	ha := &testHandle{"ha"}
	s := New(nil, nil)
	err := s.Restore(State{
		Nodes: []NodeEntry{
			{ID: 1, Inode: 1, Generation: 2, Refs: 3},
			{ID: 3, Inode: 30, Generation: 4, Refs: 2, Node: a},
			{ID: 6, Inode: 60, Generation: 1, Refs: 1, Node: b},
		},
		Handles:        []HandleEntry{{ID: 2, Handle: ha}},
		NodeGeneration: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.initTables(root); err != nil {
		t.Fatal(err)
	}

	if got := s.node[1]; got.node != Node(root) || got.refs != 3 || got.generation != 2 {
		t.Errorf("root = %+v", got)
	}
	if got := s.getHandle(2); got == nil || got.handle != Handle(ha) {
		t.Errorf("handle 2 = %+v", got)
	}

	// A restored node keeps its ID when the kernel looks it up again.
	if id, gen := s.saveNode(30, a); id != 3 || gen != 4 {
		t.Errorf("saveNode(a) = %d, %d; want 3, 4", id, gen)
	}
	if got := s.node[3].refs; got != 3 {
		t.Errorf("refs of a = %d, want 3", got)
	}

	// The kernel's old references can be forgotten as usual.
	if !s.dropNode(6, 1) {
		t.Error("dropNode(6) did not forget the node")
	}

	// New nodes get free IDs and generations never used before, both when
	// they reuse a free ID and when they go past the restored IDs.
	seen := map[fuse.NodeID]bool{}
	for i := 0; i < 6; i++ {
		id, gen := s.saveNode(uint64(100+i), &testNode{fmt.Sprint("new", i)})
		if id == 1 || id == 3 || seen[id] {
			t.Errorf("new node got ID %d, which is in use", id)
		}
		seen[id] = true
		if gen <= 5 {
			t.Errorf("ID %d got old generation %d", id, gen)
		}
	}
	if len(s.node) != 9 {
		t.Errorf("node table has %d slots, want 9", len(s.node))
	}
	if h := s.saveHandle(&testHandle{"new"}); h != 1 {
		t.Errorf("new handle got ID %d, want the free ID 1", h)
	}
	if h := s.saveHandle(&testHandle{"new2"}); h != 3 {
		t.Errorf("second new handle got ID %d, want 3", h)
	}
}

func TestRestoreRejectsBadState(t *testing.T) {
	a := &testNode{"a"}
	h := &testHandle{"h"}
	tests := []struct {
		name string
		st   State
	}{
		{"node ID 0", State{Nodes: []NodeEntry{{ID: 0, Refs: 1, Node: a}}}},
		{"duplicate node ID", State{Nodes: []NodeEntry{{ID: 2, Refs: 1, Node: a}, {ID: 2, Refs: 1, Node: &testNode{"b"}}}}},
		{"no references", State{Nodes: []NodeEntry{{ID: 2, Node: a}}}},
		{"no node", State{Nodes: []NodeEntry{{ID: 2, Refs: 1}}}},
		{"repeated node", State{Nodes: []NodeEntry{{ID: 2, Refs: 1, Node: a}, {ID: 3, Refs: 1, Node: a}}}},
		{"handle ID 0", State{Handles: []HandleEntry{{ID: 0, Handle: h}}}},
		{"duplicate handle ID", State{Handles: []HandleEntry{{ID: 1, Handle: h}, {ID: 1, Handle: h}}}},
		{"no handle", State{Handles: []HandleEntry{{ID: 1}}}},
		{"huge node ID", State{Nodes: []NodeEntry{{ID: ^fuse.NodeID(0), Refs: 1, Node: a}}}},
		{"huge handle ID", State{Handles: []HandleEntry{{ID: ^fuse.HandleID(0), Handle: h}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := New(nil, nil).Restore(tt.st); err == nil {
				t.Error("Restore accepted the state")
			}
		})
	}
}

// TestRestoreNewIDGetsNewGeneration covers an ID above the restored ones. The
// earlier server may have used and forgotten it at the highest generation.
func TestRestoreNewIDGetsNewGeneration(t *testing.T) {
	s := New(nil, nil)
	err := s.Restore(State{
		Nodes:          []NodeEntry{{ID: 2, Inode: 20, Generation: 1, Refs: 1, Node: &testNode{"a"}}},
		NodeGeneration: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.initTables(&testNode{"root"}); err != nil {
		t.Fatal(err)
	}
	id, gen := s.saveNode(30, &testNode{"new"})
	if id != 3 {
		t.Errorf("new node got ID %d, want 3", id)
	}
	if gen <= 5 {
		t.Errorf("new node got generation %d, want more than 5", gen)
	}
}

func TestRestoreRejectsRootAsOtherNode(t *testing.T) {
	root := &testNode{"root"}
	s := New(nil, nil)
	if err := s.Restore(State{Nodes: []NodeEntry{{ID: 2, Refs: 1, Node: root}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.initTables(root); err == nil {
		t.Error("initTables accepted the root node under another ID")
	}
}

func TestRestoreAfterServeFails(t *testing.T) {
	s := New(nil, nil)
	if err := s.initTables(&testNode{"root"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(State{}); err == nil {
		t.Error("Restore succeeded on a server that has started")
	}
}

func TestRestoreCopiesState(t *testing.T) {
	a := &testNode{"a"}
	nodes := []NodeEntry{{ID: 2, Refs: 1, Node: a}}
	s := New(nil, nil)
	if err := s.Restore(State{Nodes: nodes}); err != nil {
		t.Fatal(err)
	}
	nodes[0].ID = 0
	if err := s.initTables(&testNode{"root"}); err != nil {
		t.Fatal(err)
	}
	if s.node[2] == nil || s.node[2].node != Node(a) {
		t.Error("a change to the caller's slice reached the server")
	}
}

// liveFS has one file, "hello", below its root.
type liveFS struct{}

func (liveFS) Root() (Node, error) { return liveDir{}, nil }

type liveDir struct{}

func (liveDir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = os.ModeDir | 0o700
	return nil
}

func (liveDir) Lookup(ctx context.Context, name string) (Node, error) {
	if name == "hello" {
		return &testNode{name}, nil
	}
	return nil, syscall.ENOENT
}

// isMounted reports whether dir is a mount point.
func isMounted(dir string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == dir {
			return true
		}
	}
	return false
}

// TestAdoptedMountAnswers mounts a file system, leaves the Conn from Mount
// unserved, and serves a duplicate of its descriptor through Adopt. The
// kernel accepts answers on the adopted descriptor without a second INIT.
func TestAdoptedMountAnswers(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("no FUSE device: %v", err)
	}
	if _, err := exec.LookPath("fusermount"); err != nil {
		t.Skipf("no fusermount: %v", err)
	}
	dir := t.TempDir()
	mounted, err := fuse.Mount(dir, fuse.FSName("adopttest"))
	if err != nil {
		t.Skipf("cannot mount: %v", err)
	}
	defer mounted.Close()
	t.Cleanup(func() {
		// The test unmounts on success, so this normally finds nothing. A
		// lazy unmount also works while a stuck stat holds the mount busy.
		if isMounted(dir) {
			if out, err := exec.Command("fusermount", "-u", "-z", dir).CombinedOutput(); err != nil {
				t.Errorf("cleanup unmount: %v: %s", err, out)
			}
		}
	})

	fd, err := syscall.Dup(int(mounted.File().Fd()))
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := fuse.Adopt(os.NewFile(uintptr(fd), "/dev/fuse"), mounted.Protocol())
	if err != nil {
		t.Fatal(err)
	}
	defer adopted.Close()

	served := make(chan error, 1)
	go func() { served <- New(adopted, nil).Serve(liveFS{}) }()

	statted := make(chan error, 1)
	go func() {
		_, err := os.Stat(filepath.Join(dir, "hello"))
		statted <- err
	}()
	select {
	case err := <-statted:
		if err != nil {
			t.Errorf("stat through the adopted descriptor: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("stat through the adopted descriptor did not return")
	}

	if err := fuse.Unmount(dir); err != nil {
		t.Fatalf("unmount: %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Error("Serve did not return after the unmount")
	}
}
