// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"encoding/binary"
	"os"
	"syscall"
	"testing"
	"time"

	"upspin.io/client"
	"upspin.io/third_party/fuse"
	"upspin.io/third_party/fuse/fs"
	"upspin.io/upspin"
)

// fakeKernel plays the kernel side of a FUSE connection over a socket pair
// that keeps message boundaries.
type fakeKernel struct {
	t      *testing.T
	fd     int
	unique uint64
}

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

// call sends a request and returns the error number and body of the answer.
func (k *fakeKernel) call(op uint32, node uint64, args []byte) (syscall.Errno, []byte) {
	k.t.Helper()
	const inHeaderSize, outHeaderSize = 40, 16
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
	buf := make([]byte, 1<<16)
	for {
		n, err := syscall.Read(k.fd, buf)
		if err != nil {
			k.t.Fatalf("reading the answer to op %d: %v", op, err)
		}
		if n < outHeaderSize {
			k.t.Fatalf("short answer to op %d: %x", op, buf[:n])
		}
		buf = buf[:n]
		if binary.NativeEndian.Uint64(buf[8:]) != 0 {
			break
		}
		// A notification from the server, such as a cache invalidation.
		buf = buf[:cap(buf)]
	}
	if binary.NativeEndian.Uint64(buf[8:]) != k.unique {
		k.t.Fatalf("answer to request %d, want %d", binary.NativeEndian.Uint64(buf[8:]), k.unique)
	}
	n := len(buf)
	return syscall.Errno(-int32(binary.NativeEndian.Uint32(buf[4:]))), buf[outHeaderSize:n]
}

// lookup returns the node ID and generation of name in the directory parent.
func (k *fakeKernel) lookup(parent uint64, name string) (id, gen uint64) {
	k.t.Helper()
	const opLookup = 1
	errno, body := k.call(opLookup, parent, append([]byte(name), 0))
	if errno != 0 {
		k.t.Fatalf("lookup %q: %v", name, errno)
	}
	return binary.NativeEndian.Uint64(body[0:]), binary.NativeEndian.Uint64(body[8:])
}

// rename renames oldName in the directory dir to newName in the same
// directory.
func (k *fakeKernel) rename(dir uint64, oldName, newName string) {
	k.t.Helper()
	const opRename = 12
	args := make([]byte, 8, 8+len(oldName)+len(newName)+2)
	binary.NativeEndian.PutUint64(args, dir)
	args = append(append(append(append(args, oldName...), 0), newName...), 0)
	if errno, _ := k.call(opRename, dir, args); errno != 0 {
		k.t.Fatalf("rename %q to %q: %v", oldName, newName, errno)
	}
}

// getattr returns the inode number and size of a node.
func (k *fakeKernel) getattr(node uint64) (errno syscall.Errno, inode, size uint64) {
	k.t.Helper()
	const opGetattr = 3
	errno, body := k.call(opGetattr, node, make([]byte, 16))
	if errno != 0 {
		return errno, 0, 0
	}
	// fuse_attr_out: attr_valid, attr_valid_nsec, dummy, then the attributes,
	// which start with the inode number and the size.
	return 0, binary.NativeEndian.Uint64(body[16:]), binary.NativeEndian.Uint64(body[24:])
}

// serveFS serves f over a fake kernel connection, optionally from saved
// tables. The returned function ends the connection and waits for Serve.
func serveFS(t *testing.T, f *upspinFS, st *fs.State) (*fakeKernel, func()) {
	t.Helper()
	conn, kernel := newFakeConn(t)
	f.server = fs.New(conn, &fs.Config{Observer: f})
	if st != nil {
		if err := f.server.Restore(*st); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(f) }()
	return kernel, func() {
		kernel.close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("Serve did not return")
		}
		conn.Close()
	}
}

// TestRestartKeepsNodes runs one upspinfs over a fake kernel connection,
// stops it, and starts a second one from the journal. The second one answers
// for the node IDs the kernel got from the first.
func TestRestartKeepsNodes(t *testing.T) {
	user := testConfig.user
	c := client.New(testConfig.cfg)
	dir := upspin.PathName(user + "/restart")
	if _, err := c.MakeDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(dir+"/file", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(dir+"/gone", []byte("bye")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(dir+"/src", []byte("source")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(dir+"/dst", []byte("target")); err != nil {
		t.Fatal(err)
	}

	jf := tempJournal(t)
	j, _ := mustOpenJournal(t, jf)
	first := newUpspinFS(testConfig.cfg, t.TempDir(), t.TempDir(), maxBytes)
	first.journal = j
	kernel, stop := serveFS(t, first, nil)
	userID, _ := kernel.lookup(1, user)
	dirID, _ := kernel.lookup(userID, "restart")
	fileID, fileGen := kernel.lookup(dirID, "file")
	goneID, _ := kernel.lookup(dirID, "gone")
	dstID, _ := kernel.lookup(dirID, "dst")
	srcID, srcGen := kernel.lookup(dirID, "src")
	// The rename moves src over dst. The kernel keeps both IDs: srcID now
	// names dst, and dstID names a file without a path.
	kernel.rename(dirID, "src", "dst")
	errno, fileInode, size := kernel.getattr(fileID)
	if errno != 0 || size != 5 {
		t.Fatalf("getattr before the restart: %v, size %d", errno, size)
	}
	stop()
	if first.journal == nil {
		t.Fatal("the journal failed")
	}

	// The file goes away while no upspinfs runs.
	if err := c.Delete(dir + "/gone"); err != nil {
		t.Fatal(err)
	}

	j, st := mustOpenJournal(t, jf)
	second := newUpspinFS(testConfig.cfg, t.TempDir(), t.TempDir(), maxBytes)
	second.journal = j
	tables := second.restore(st)
	kernel, stop = serveFS(t, second, &tables)
	defer stop()

	errno, inode, size := kernel.getattr(fileID)
	if errno != 0 {
		t.Fatalf("getattr of a restored node: %v", errno)
	}
	if inode != fileInode || size != 5 {
		t.Errorf("restored node: inode %d size %d, want inode %d size 5", inode, size, fileInode)
	}
	if id, gen := kernel.lookup(dirID, "file"); id != fileID || gen != fileGen {
		t.Errorf("lookup after the restart = %d, %d; want %d, %d", id, gen, fileID, fileGen)
	}
	if errno, _, _ := kernel.getattr(goneID); errno != syscall.ENOENT {
		t.Errorf("getattr of a node deleted during the restart: %v, want ENOENT", errno)
	}
	if errno, _, size := kernel.getattr(srcID); errno != 0 || size != uint64(len("source")) {
		t.Errorf("getattr of the renamed node: %v, size %d", errno, size)
	}
	if id, gen := kernel.lookup(dirID, "dst"); id != srcID || gen != srcGen {
		t.Errorf("lookup of the rename target = %d, %d; want %d, %d", id, gen, srcID, srcGen)
	}
	if errno, _, _ := kernel.getattr(dstID); errno != syscall.ENOENT {
		t.Errorf("getattr of the node renamed over: %v, want ENOENT", errno)
	}

	// A new node gets an inode number the first process did not use.
	newID, _ := kernel.lookup(userID, "restart")
	if newID != dirID {
		t.Errorf("directory lookup after the restart = %d, want %d", newID, dirID)
	}
	if _, err := c.Put(dir+"/new", []byte("x")); err != nil {
		t.Fatal(err)
	}
	newFileID, _ := kernel.lookup(dirID, "new")
	if _, newInode, _ := kernel.getattr(newFileID); newInode <= fileInode {
		t.Errorf("new inode %d is not above the restored %d", newInode, fileInode)
	}
}

// TestForgottenNodeLeavesJournal checks that a node the kernel forgot cannot
// change the journal entry of the next node that gets its ID.
func TestForgottenNodeLeavesJournal(t *testing.T) {
	j, _ := mustOpenJournal(t, tempJournal(t))
	f := newUpspinFS(testConfig.cfg, t.TempDir(), t.TempDir(), maxBytes)
	f.journal = j
	old := &node{f: f, jpath: "u@x.com/a", jmapped: true}
	f.NodeSaved(fs.NodeEntry{ID: 5, Inode: 9, Refs: 1, Node: old})
	f.NodeRemoved(5)
	reuser := &node{f: f, jpath: "u@x.com/b", jmapped: true}
	f.NodeSaved(fs.NodeEntry{ID: 5, Inode: 10, Generation: 1, Refs: 1, Node: reuser})

	f.Lock()
	f.setMapped(old, false)
	f.setPath(old, "u@x.com/elsewhere")
	f.Unlock()

	want := journalNode{inode: 10, gen: 1, refs: 1, path: "u@x.com/b", mapped: true}
	if got := j.live.nodes[5]; got != want {
		t.Errorf("journal entry of ID 5 = %+v, want %+v", got, want)
	}
}

// TestRestoreReleasesLostHandles checks that handles which cannot be restored
// leave the journal, so that they are not reported again.
func TestRestoreReleasesLostHandles(t *testing.T) {
	jf := tempJournal(t)
	j, _ := mustOpenJournal(t, jf)
	j.putNode(2, journalNode{inode: 5, refs: 1, path: testConfig.user + "/x", mapped: true})
	j.putHandle(3, journalHandle{node: 2})
	j, st := mustOpenJournal(t, jf)
	f := newUpspinFS(testConfig.cfg, t.TempDir(), t.TempDir(), maxBytes)
	f.journal = j
	f.restore(st)
	if len(j.live.handles) != 0 {
		t.Errorf("handles after restore: %v", j.live.handles)
	}
}
