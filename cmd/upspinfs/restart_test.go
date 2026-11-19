// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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
	n, err := syscall.Read(k.fd, buf)
	if err != nil {
		k.t.Fatalf("reading the answer to op %d: %v", op, err)
	}
	if n < outHeaderSize || binary.NativeEndian.Uint64(buf[8:]) != k.unique {
		k.t.Fatalf("bad answer to op %d: %x", op, buf[:n])
	}
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

	jf := tempJournal(t)
	j, _ := mustOpenJournal(t, jf)
	first := newUpspinFS(testConfig.cfg, t.TempDir(), t.TempDir(), maxBytes)
	first.journal = j
	kernel, stop := serveFS(t, first, nil)
	userID, _ := kernel.lookup(1, user)
	dirID, _ := kernel.lookup(userID, "restart")
	fileID, fileGen := kernel.lookup(dirID, "file")
	goneID, _ := kernel.lookup(dirID, "gone")
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
