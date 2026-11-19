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
		if err == syscall.EINTR {
			continue
		}
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

// FUSE operation codes used below.
const (
	opRead    = 15
	opWrite   = 16
	opRelease = 18
	opOpen    = 14
	opCreate  = 35
)

// open opens a file and returns the handle.
func (k *fakeKernel) open(node uint64, flags uint32) uint64 {
	k.t.Helper()
	args := make([]byte, 8)
	binary.NativeEndian.PutUint32(args, flags)
	errno, body := k.call(opOpen, node, args)
	if errno != 0 {
		k.t.Fatalf("open of node %d: %v", node, errno)
	}
	return binary.NativeEndian.Uint64(body)
}

// create creates and opens name in the directory parent.
func (k *fakeKernel) create(parent uint64, name string, flags uint32) (id, handle uint64) {
	k.t.Helper()
	args := make([]byte, 16, 16+len(name)+1)
	binary.NativeEndian.PutUint32(args[0:], flags)
	binary.NativeEndian.PutUint32(args[4:], 0o600)
	args = append(append(args, name...), 0)
	errno, body := k.call(opCreate, parent, args)
	if errno != 0 {
		k.t.Fatalf("create %q: %v", name, errno)
	}
	// The entry comes first and the open result, 16 bytes, last.
	return binary.NativeEndian.Uint64(body), binary.NativeEndian.Uint64(body[len(body)-16:])
}

func (k *fakeKernel) write(node, handle uint64, off int64, data string) syscall.Errno {
	k.t.Helper()
	args := make([]byte, 40, 40+len(data))
	binary.NativeEndian.PutUint64(args[0:], handle)
	binary.NativeEndian.PutUint64(args[8:], uint64(off))
	binary.NativeEndian.PutUint32(args[16:], uint32(len(data)))
	errno, _ := k.call(opWrite, node, append(args, data...))
	return errno
}

func (k *fakeKernel) read(node, handle uint64, size uint32) (syscall.Errno, string) {
	k.t.Helper()
	args := make([]byte, 40)
	binary.NativeEndian.PutUint64(args[0:], handle)
	binary.NativeEndian.PutUint32(args[16:], size)
	errno, body := k.call(opRead, node, args)
	return errno, string(body)
}

func (k *fakeKernel) release(node, handle uint64) syscall.Errno {
	k.t.Helper()
	args := make([]byte, 24)
	binary.NativeEndian.PutUint64(args[0:], handle)
	errno, _ := k.call(opRelease, node, args)
	return errno
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

// TestRestoreReleasesLostHandles checks that a handle of a node the journal
// does not know leaves the journal, so that it is not reported again.
func TestRestoreReleasesLostHandles(t *testing.T) {
	jf := tempJournal(t)
	j, _ := mustOpenJournal(t, jf)
	j.putNode(2, journalNode{inode: 5, refs: 1, path: testConfig.user + "/x", mapped: true})
	j.putHandle(3, journalHandle{node: 2})
	j.putHandle(4, journalHandle{node: 9})
	j, st := mustOpenJournal(t, jf)
	f := newUpspinFS(testConfig.cfg, t.TempDir(), t.TempDir(), maxBytes)
	f.journal = j
	tables := f.restore(st)
	if len(tables.Handles) != 1 || tables.Handles[0].ID != 3 {
		t.Errorf("restored handles: %+v", tables.Handles)
	}
	if _, ok := j.live.handles[4]; ok || len(j.live.handles) != 1 {
		t.Errorf("handles in the journal after restore: %v", j.live.handles)
	}
}

// TestRestartKeepsOpenFiles stops upspinfs while a file is open for reading
// and a new file holds writes that were not put. The next upspinfs serves
// both handles and puts the unsaved writes.
func TestRestartKeepsOpenFiles(t *testing.T) {
	const (
		oRDONLY = 0
		oRDWR   = 2
	)
	user := testConfig.user
	c := client.New(testConfig.cfg)
	dir := upspin.PathName(user + "/reopen")
	if _, err := c.MakeDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(dir+"/readme", []byte("read me")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(dir+"/edit", []byte("original")); err != nil {
		t.Fatal(err)
	}

	jf := tempJournal(t)
	j, _ := mustOpenJournal(t, jf)
	cacheDir := t.TempDir()
	first := newUpspinFS(testConfig.cfg, t.TempDir(), cacheDir, maxBytes)
	first.journal = j
	kernel, stop := serveFS(t, first, nil)
	userID, _ := kernel.lookup(1, user)
	dirID, _ := kernel.lookup(userID, "reopen")
	readID, _ := kernel.lookup(dirID, "readme")
	readFh := kernel.open(readID, oRDONLY)
	if errno, data := kernel.read(readID, readFh, 100); errno != 0 || data != "read me" {
		t.Fatalf("read before the restart: %v, %q", errno, data)
	}
	newID, newFh := kernel.create(dirID, "new", oRDWR)
	if errno := kernel.write(newID, newFh, 0, "unsaved data"); errno != 0 {
		t.Fatalf("write before the restart: %v", errno)
	}
	// A change to an existing file: its write back is conditioned on the
	// sequence the file had when it was opened.
	editID, _ := kernel.lookup(dirID, "edit")
	editFh := kernel.open(editID, oRDWR)
	if errno := kernel.write(editID, editFh, 0, "EDIT"); errno != 0 {
		t.Fatalf("write to an existing file before the restart: %v", errno)
	}
	// A file the kernel releases after the restart, before the restored
	// writes are put.
	earlyID, earlyFh := kernel.create(dirID, "early", oRDWR)
	if errno := kernel.write(earlyID, earlyFh, 0, "released early"); errno != 0 {
		t.Fatalf("write before the restart: %v", errno)
	}
	// upspinfs dies before the kernel releases either handle.
	stop()
	if first.journal == nil {
		t.Fatal("the journal failed")
	}
	if data, err := c.Get(dir + "/new"); err == nil && string(data) == "unsaved data" {
		t.Fatal("the write reached the store before the restart; the test proves nothing")
	}

	j, st := mustOpenJournal(t, jf)
	second := newUpspinFS(testConfig.cfg, t.TempDir(), cacheDir, maxBytes)
	second.journal = j
	tables := second.restore(st)
	kernel, stop = serveFS(t, second, &tables)
	defer stop()

	if errno, data := kernel.read(newID, newFh, 100); errno != 0 || data != "unsaved data" {
		t.Errorf("read of the unsaved writes after the restart: %v, %q", errno, data)
	}
	if errno, data := kernel.read(readID, readFh, 100); errno != 0 || data != "read me" {
		t.Errorf("read through the restored read handle: %v, %q", errno, data)
	}

	if errno := kernel.release(earlyID, earlyFh); errno != 0 {
		t.Errorf("release before the restored writes are put: %v", errno)
	}
	second.finishRestoredWrites()
	if data, err := c.Get(dir + "/new"); err != nil || string(data) != "unsaved data" {
		t.Errorf("store after finishRestoredWrites: %v, %q", err, data)
	}
	if data, err := c.Get(dir + "/edit"); err != nil || string(data) != "EDITinal" {
		t.Errorf("edited file after finishRestoredWrites: %v, %q", err, data)
	}
	if data, err := c.Get(dir + "/early"); err != nil || string(data) != "released early" {
		t.Errorf("file released after the restart: %v, %q", err, data)
	}
	if errno := kernel.release(editID, editFh); errno != 0 {
		t.Errorf("release of the edited file: %v", errno)
	}
	second.jmu.Lock()
	caches := len(second.journal.live.caches)
	second.jmu.Unlock()
	if caches != 0 {
		t.Errorf("%d cache files in the journal after the write back", caches)
	}

	// The restored handle keeps working.
	if errno := kernel.write(newID, newFh, int64(len("unsaved data")), " and more"); errno != 0 {
		t.Errorf("write after the restart: %v", errno)
	}
	if errno := kernel.release(newID, newFh); errno != 0 {
		t.Errorf("release after the restart: %v", errno)
	}
	if errno := kernel.release(readID, readFh); errno != 0 {
		t.Errorf("release of the read handle: %v", errno)
	}
	if data, err := c.Get(dir + "/new"); err != nil || string(data) != "unsaved data and more" {
		t.Errorf("store after release: %v, %q", err, data)
	}
	second.jmu.Lock()
	handles := len(second.journal.live.handles)
	second.jmu.Unlock()
	if handles != 0 {
		t.Errorf("%d handles in the journal after both releases", handles)
	}
}

// TestRestoreDropsUnusableCaches checks that cache records which cannot be
// restored leave the journal: a missing cache file, and a file that lost its
// path before the restart.
func TestRestoreDropsUnusableCaches(t *testing.T) {
	jf := tempJournal(t)
	j, _ := mustOpenJournal(t, jf)
	key := make([]byte, 32)
	j.putNode(2, journalNode{inode: 5, refs: 1, path: testConfig.user + "/missing", mapped: true})
	j.putCache(2, journalCache{seq: 1, fname: "/nonexistent/cache/file", key: key})
	j.putNode(3, journalNode{inode: 6, refs: 1, path: testConfig.user + "/unlinked"})
	j.putCache(3, journalCache{seq: 1, fname: "/nonexistent/other", key: key})
	j, st := mustOpenJournal(t, jf)
	f := newUpspinFS(testConfig.cfg, t.TempDir(), t.TempDir(), maxBytes)
	f.journal = j
	f.restore(st)
	if len(j.live.caches) != 0 || len(f.restoredWrites) != 0 {
		t.Errorf("after restore: journal caches %v, restored writes %d", j.live.caches, len(f.restoredWrites))
	}
}

// TestReusedIDDropsCacheRecord checks that a node which takes over a kernel
// ID does not inherit the cache record of the node that had it.
func TestReusedIDDropsCacheRecord(t *testing.T) {
	j, _ := mustOpenJournal(t, tempJournal(t))
	f := newUpspinFS(testConfig.cfg, t.TempDir(), t.TempDir(), maxBytes)
	f.journal = j
	old := &node{f: f, jpath: "u@x.com/a", jmapped: true, jcache: &journalCache{seq: 1, fname: "/c/tmp/1"}}
	f.NodeSaved(fs.NodeEntry{ID: 5, Inode: 9, Refs: 1, Node: old})
	// The Forget for old was missed; the server gives its ID to another node.
	reuser := &node{f: f, jpath: "u@x.com/b", jmapped: true}
	f.NodeSaved(fs.NodeEntry{ID: 5, Inode: 10, Generation: 1, Refs: 1, Node: reuser})
	if c, ok := j.live.caches[5]; ok {
		t.Errorf("ID 5 kept the cache record %+v of its earlier node", c)
	}
}
