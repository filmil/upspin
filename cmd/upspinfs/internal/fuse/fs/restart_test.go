// SPDX-License-Identifier: Apache-2.0

package fs

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"upspin.io/cmd/upspinfs/internal/fuse"
)

// The FUSE message layout used by fakeKernel.
const (
	inHeaderSize  = 40
	outHeaderSize = 16
	opLookup      = 1
	opForget      = 2
	opGetattr     = 3
	opRead        = 15
)

// fakeKernel plays the kernel side of a FUSE connection over a socket pair
// that keeps message boundaries.
type fakeKernel struct {
	t      *testing.T
	fd     int
	unique uint64
}

// newFakeConn returns a Conn for the server and the kernel side for the test.
func newFakeConn(t *testing.T) (*fuse.Conn, *fakeKernel) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := fuse.Adopt(os.NewFile(uintptr(fds[0]), "fake-fuse"), fuse.Protocol{Major: 7, Minor: 12})
	if err != nil {
		t.Fatal(err)
	}
	tv := syscall.NsecToTimeval(int64(30 * time.Second))
	if err := syscall.SetsockoptTimeval(fds[1], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	return conn, &fakeKernel{t: t, fd: fds[1]}
}

func (k *fakeKernel) close() {
	k.t.Helper()
	if err := syscall.Close(k.fd); err != nil {
		k.t.Fatal(err)
	}
}

func (k *fakeKernel) send(op uint32, node uint64, args []byte) uint64 {
	k.t.Helper()
	k.unique += 2
	msg := make([]byte, inHeaderSize+len(args))
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.NativeEndian.PutUint32(msg[4:], op)
	binary.NativeEndian.PutUint64(msg[8:], k.unique)
	binary.NativeEndian.PutUint64(msg[16:], node)
	copy(msg[inHeaderSize:], args)
	if _, err := syscall.Write(k.fd, msg); err != nil {
		k.t.Fatal(err)
	}
	return k.unique
}

// call sends a request and returns the error number and body of its answer.
func (k *fakeKernel) call(op uint32, node uint64, args []byte) (syscall.Errno, []byte) {
	k.t.Helper()
	unique := k.send(op, node, args)
	buf := make([]byte, 1<<16)
	n, err := syscall.Read(k.fd, buf)
	if err != nil {
		k.t.Fatalf("reading the answer to op %d: %v", op, err)
	}
	if n < outHeaderSize {
		k.t.Fatalf("answer of %d bytes", n)
	}
	if got := binary.NativeEndian.Uint64(buf[8:]); got != unique {
		k.t.Fatalf("answer for request %d, want %d", got, unique)
	}
	errno := -int32(binary.NativeEndian.Uint32(buf[4:]))
	return syscall.Errno(errno), buf[outHeaderSize:n]
}

func (k *fakeKernel) lookup(parent uint64, name string) (id, generation uint64) {
	k.t.Helper()
	errno, body := k.call(opLookup, parent, append([]byte(name), 0))
	if errno != 0 {
		k.t.Fatalf("lookup %q: %v", name, errno)
	}
	return binary.NativeEndian.Uint64(body[0:]), binary.NativeEndian.Uint64(body[8:])
}

func (k *fakeKernel) getattr(node uint64) syscall.Errno {
	k.t.Helper()
	errno, _ := k.call(opGetattr, node, make([]byte, 16))
	return errno
}

func (k *fakeKernel) forget(node, count uint64) {
	k.t.Helper()
	args := make([]byte, 8)
	binary.NativeEndian.PutUint64(args, count)
	k.send(opForget, node, args)
}

func (k *fakeKernel) read(node, handle uint64, size uint32) (syscall.Errno, []byte) {
	k.t.Helper()
	args := make([]byte, 40)
	binary.NativeEndian.PutUint64(args[0:], handle)
	binary.NativeEndian.PutUint32(args[16:], size)
	return k.call(opRead, node, args)
}

// journal is a TableObserver that keeps the tables, as upspinfs will.
type journal struct {
	sync.Mutex
	st      State
	nodes   map[fuse.NodeID]NodeEntry
	handles map[fuse.HandleID]HandleEntry
}

func newJournal() *journal {
	return &journal{
		nodes:   make(map[fuse.NodeID]NodeEntry),
		handles: make(map[fuse.HandleID]HandleEntry),
	}
}

func (j *journal) NodeSaved(e NodeEntry) {
	j.Lock()
	defer j.Unlock()
	j.nodes[e.ID] = e
	if e.Generation > j.st.NodeGeneration {
		j.st.NodeGeneration = e.Generation
	}
}

func (j *journal) NodeRemoved(id fuse.NodeID) {
	j.Lock()
	defer j.Unlock()
	delete(j.nodes, id)
}

func (j *journal) HandleSaved(e HandleEntry) {
	j.Lock()
	defer j.Unlock()
	j.handles[e.ID] = e
}

func (j *journal) HandleRemoved(id fuse.HandleID) {
	j.Lock()
	defer j.Unlock()
	delete(j.handles, id)
}

func (j *journal) state() State {
	j.Lock()
	defer j.Unlock()
	st := State{NodeGeneration: j.st.NodeGeneration}
	for _, e := range j.nodes {
		st.Nodes = append(st.Nodes, e)
	}
	for _, e := range j.handles {
		st.Handles = append(st.Handles, e)
	}
	return st
}

// restartFS serves a fixed set of nodes below its root.
type restartFS struct{ nodes map[string]*restartNode }

func (f *restartFS) Root() (Node, error) { return restartRoot{f}, nil }

type restartRoot struct{ f *restartFS }

func (restartRoot) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = os.ModeDir | 0o700
	return nil
}

func (r restartRoot) Lookup(ctx context.Context, name string) (Node, error) {
	if n, ok := r.f.nodes[name]; ok {
		return n, nil
	}
	return nil, syscall.ENOENT
}

type restartNode struct {
	forgotten chan struct{}
}

func (*restartNode) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Mode = 0o600
	return nil
}

func (n *restartNode) Forget() { close(n.forgotten) }

type restartHandle struct{ data []byte }

func (h *restartHandle) ReadAll(ctx context.Context) ([]byte, error) { return h.data, nil }

// TestServeAfterRestart runs a server until its connection ends, starts a
// second server from what the observer recorded, and sends the second server
// the IDs the kernel would still hold.
func TestServeAfterRestart(t *testing.T) {
	hello := &restartNode{forgotten: make(chan struct{})}
	gone := &restartNode{forgotten: make(chan struct{})}
	filesys := &restartFS{nodes: map[string]*restartNode{"hello": hello, "gone": gone}}
	rec := newJournal()

	conn, kernel := newFakeConn(t)
	first := New(conn, &Config{Observer: rec})
	done := make(chan error, 1)
	go func() { done <- first.Serve(filesys) }()

	helloID, helloGen := kernel.lookup(1, "hello")
	kernel.lookup(1, "hello")
	goneID, _ := kernel.lookup(1, "gone")
	kernel.forget(goneID, 1)
	select {
	case <-gone.forgotten:
	case <-time.After(30 * time.Second):
		t.Fatal("the first server did not forget the node")
	}
	kernel.close()
	if err := <-done; err != nil {
		t.Fatalf("first Serve: %v", err)
	}
	conn.Close()

	st := rec.state()
	st.Handles = append(st.Handles, HandleEntry{ID: 5, Handle: &restartHandle{data: []byte("restored")}})

	conn, kernel = newFakeConn(t)
	defer conn.Close()
	second := New(conn, nil)
	if err := second.Restore(st); err != nil {
		t.Fatal(err)
	}
	go func() { done <- second.Serve(filesys) }()

	if errno := kernel.getattr(helloID); errno != 0 {
		t.Errorf("getattr of a restored node: %v", errno)
	}
	if errno := kernel.getattr(goneID); errno != syscall.ESTALE {
		t.Errorf("getattr of a forgotten node: got %v, want ESTALE", errno)
	}
	errno, data := kernel.read(helloID, 5, 100)
	if errno != 0 || !bytes.Equal(data, []byte("restored")) {
		t.Errorf("read through a restored handle: %v, %q", errno, data)
	}

	// A new lookup of a restored node finds the same ID.
	if id, gen := kernel.lookup(1, "hello"); id != helloID || gen != helloGen {
		t.Errorf("lookup after restart = %d, %d; want %d, %d", id, gen, helloID, helloGen)
	}

	// The node has three references: two from the first server, one from
	// the second. Only the last Forget reaches the file system.
	kernel.forget(helloID, 2)
	if errno := kernel.getattr(helloID); errno != 0 {
		t.Errorf("getattr with one reference left: %v", errno)
	}
	select {
	case <-hello.forgotten:
		t.Error("node forgotten while the kernel still holds a reference")
	default:
	}
	kernel.forget(helloID, 1)
	select {
	case <-hello.forgotten:
	case <-time.After(30 * time.Second):
		t.Error("the restored node was not forgotten")
	}

	kernel.close()
	if err := <-done; err != nil {
		t.Errorf("second Serve: %v", err)
	}
}
