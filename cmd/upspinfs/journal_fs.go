// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main // import "upspin.io/cmd/upspinfs"

import (
	"os"
	"sort"
	"strings"
	"time"

	"upspin.io/cmd/upspinfs/internal/ose"
	"upspin.io/errors"
	"upspin.io/log"
	"upspin.io/path"
	"upspin.io/third_party/fuse"
	"upspin.io/third_party/fuse/fs"
	"upspin.io/upspin"
)

// This file connects the journal to upspinfs. upspinFS is the TableObserver
// of its FUSE server, and it records the path changes the server cannot see.

var _ fs.TableObserver = (*upspinFS)(nil)

// NodeSaved implements fs.TableObserver.
func (f *upspinFS) NodeSaved(e fs.NodeEntry) {
	n, ok := e.Node.(*node)
	if !ok {
		return
	}
	f.jmu.Lock()
	defer f.jmu.Unlock()
	if old := f.byID[e.ID]; old != nil && old != n {
		// Only after a missed Forget; the ID now names n.
		old.kernelID = 0
	}
	isNew := n.kernelID != e.ID
	n.kernelID = e.ID
	f.byID[e.ID] = n
	if f.journal == nil {
		return
	}
	f.journal.putNode(e.ID, journalNode{
		inode:  e.Inode,
		gen:    e.Generation,
		refs:   e.Refs,
		mode:   n.jmode,
		path:   n.jpath,
		mapped: n.jmapped,
	})
	if isNew && n.jcache != nil {
		// The file was created before the kernel learned its ID.
		f.journal.putCache(e.ID, *n.jcache)
	}
	f.checkJournal()
}

// NodeRemoved implements fs.TableObserver.
func (f *upspinFS) NodeRemoved(id fuse.NodeID) {
	f.jmu.Lock()
	defer f.jmu.Unlock()
	// The server may give the ID to another node at once. Later path and
	// mapping changes of the forgotten node must not reach that one.
	if n := f.byID[id]; n != nil {
		n.kernelID = 0
		delete(f.byID, id)
	}
	if f.journal != nil {
		f.journal.forgetNode(id)
		f.checkJournal()
	}
}

// HandleSaved implements fs.TableObserver.
func (f *upspinFS) HandleSaved(e fs.HandleEntry) {
	h, ok := e.Handle.(*handle)
	if !ok {
		return
	}
	f.jmu.Lock()
	defer f.jmu.Unlock()
	if f.journal != nil {
		f.journal.putHandle(e.ID, journalHandle{node: h.n.kernelID, flags: uint32(h.flags)})
		f.checkJournal()
	}
}

// HandleRemoved implements fs.TableObserver.
func (f *upspinFS) HandleRemoved(id fuse.HandleID) {
	f.jmu.Lock()
	defer f.jmu.Unlock()
	// Directory handles are not journaled, so neither is their release.
	if _, ok := f.journal.liveHandle(id); ok {
		f.journal.releaseHandle(id)
		f.checkJournal()
	}
}

// setMapped records whether f.nodeMap maps n's path to n. Called with f
// locked.
func (f *upspinFS) setMapped(n *node, mapped bool) {
	f.jmu.Lock()
	defer f.jmu.Unlock()
	if n.jmapped == mapped {
		return
	}
	n.jmapped = mapped
	if f.journal != nil && n.kernelID != 0 {
		f.journal.setMapped(n.kernelID, mapped)
		f.checkJournal()
	}
}

// setPath records a new path name for n. Called with f locked.
func (f *upspinFS) setPath(n *node, p upspin.PathName) {
	f.jmu.Lock()
	defer f.jmu.Unlock()
	n.jpath = string(p)
	if f.journal != nil && n.kernelID != 0 {
		f.journal.setPath(n.kernelID, n.jpath)
		f.checkJournal()
	}
}

// setCache records the cache file of n that holds writes not yet put, or
// that it has none (c is nil). Called with n locked.
func (f *upspinFS) setCache(n *node, c *journalCache) {
	f.jmu.Lock()
	defer f.jmu.Unlock()
	if c == nil && n.jcache == nil {
		return
	}
	n.jcache = c
	if f.journal == nil || n.kernelID == 0 {
		return
	}
	if c == nil {
		f.journal.dropCache(n.kernelID)
	} else {
		f.journal.putCache(n.kernelID, *c)
	}
	f.checkJournal()
}

// checkJournal stops journaling after the first write error. The mount keeps
// working; only a later restart loses the tables. Called with f.jmu locked.
func (f *upspinFS) checkJournal() {
	if err := f.journal.err; err != nil {
		log.Error.Printf("upspinfs: journal write failed, a restart will lose open files: %v", err)
		f.journal = nil
	}
}

// restore rebuilds the nodes in st and returns the tables for the FUSE
// server. It must run before the server starts. Every restored node with a
// path is stale: its first refresh asks the directory server for its
// attributes. A node that had lost its path answers ENOENT.
//
// Open file handles are restored, and so are cache files with writes that
// were not yet put. Call finishRestoredWrites once the server runs.
func (f *upspinFS) restore(st journalState) fs.State {
	out := fs.State{NodeGeneration: st.maxGen}
	f.Lock()
	defer f.Unlock()
	f.jmu.Lock()
	defer f.jmu.Unlock()
	ids := make([]fuse.NodeID, 0, len(st.nodes))
	for id := range st.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	for _, id := range ids {
		jn := st.nodes[id]
		if jn.inode > uint64(f.lastID) {
			f.lastID = fuse.NodeID(jn.inode)
		}
		if id == 1 {
			f.root.kernelID = 1
			f.byID[1] = f.root
			out.Nodes = append(out.Nodes, fs.NodeEntry{ID: id, Inode: jn.inode, Generation: jn.gen, Refs: jn.refs})
			continue
		}
		if _, ok := f.nodeMap[upspin.PathName(jn.path)]; ok && jn.mapped {
			// Only one node can be mapped to a path; the lowest ID keeps it.
			// The journal never records two, so this means damage.
			log.Error.Printf("upspinfs: journal maps %q to two nodes", jn.path)
			jn.mapped = false
			if f.journal != nil {
				f.journal.setMapped(id, false)
			}
		}
		n := f.restoredNode(id, jn)
		f.byID[id] = n
		out.Nodes = append(out.Nodes, fs.NodeEntry{ID: id, Inode: jn.inode, Generation: jn.gen, Refs: jn.refs, Node: n})
		if !jn.mapped {
			continue
		}
		f.nodeMap[n.uname] = n
		f.watched.add(n.uname)
		if n.t == userNode {
			f.userDirs[string(n.user)] = true
		}
	}
	keep := make(map[string]bool)
	cids := make([]fuse.NodeID, 0, len(st.caches))
	for id := range st.caches {
		cids = append(cids, id)
	}
	sort.Slice(cids, func(a, b int) bool { return cids[a] < cids[b] })
	for _, id := range cids {
		if f.restoreCache(id, st.caches[id]) {
			keep[st.caches[id].fname] = true
		}
	}
	f.cache.removeAllExcept(keep)

	hids := make([]fuse.HandleID, 0, len(st.handles))
	for id := range st.handles {
		hids = append(hids, id)
	}
	sort.Slice(hids, func(a, b int) bool { return hids[a] < hids[b] })
	for _, id := range hids {
		jh := st.handles[id]
		n := f.byID[jh.node]
		if n == nil || n == f.root {
			log.Error.Printf("upspinfs: handle %d of the earlier process names unknown node %d", id, jh.node)
			if f.journal != nil {
				f.journal.releaseHandle(id)
			}
			continue
		}
		// The cache file opens on first use; see ensureCache.
		h := allocHandle(n)
		h.flags = fuse.OpenFlags(jh.flags)
		out.Handles = append(out.Handles, fs.HandleEntry{ID: id, Handle: h})
	}
	if f.journal != nil {
		f.checkJournal()
	}
	return out
}

// restoreCache reopens the cache file of node id, which holds writes the
// earlier process did not put. Called with f and f.jmu locked.
func (f *upspinFS) restoreCache(id fuse.NodeID, c journalCache) bool {
	n := f.byID[id]
	if n == nil || n.t != otherNode {
		return false
	}
	file, err := ose.OpenFileWithKey(c.fname, os.O_RDWR, cachedFilePerms, c.key)
	if err == nil {
		var info os.FileInfo
		if info, err = file.Stat(); err == nil {
			n.cf = &cachedFile{c: f.cache, n: n, fname: c.fname, dirty: true, file: file, size: info.Size()}
			n.seq = c.seq
			n.jcache = &c
			// The cache file is newer than anything in the store.
			n.stale = false
			n.attr.Size = uint64(info.Size())
			n.attr.Blocks = (n.attr.Size + 511) / 512
			f.restoredWrites = append(f.restoredWrites, n)
			return true
		}
		file.Close()
	}
	log.Error.Printf("upspinfs: unsaved writes to %q are lost: %v", n.uname, err)
	if f.journal != nil {
		f.journal.dropCache(id)
	}
	return false
}

// finishRestoredWrites puts the restored cache files with unsaved writes. The
// kernel may never release their handles: a release in flight at the crash is
// lost. Call it after the server started, since a put invalidates the
// kernel's caches.
func (f *upspinFS) finishRestoredWrites() {
	f.Lock()
	nodes := f.restoredWrites
	f.restoredWrites = nil
	f.Unlock()
	for _, n := range nodes {
		n.Lock()
		if err := n.cf.writeback(n); err != nil {
			log.Error.Printf("upspinfs: writing back %q after a restart: %v", n.uname, err)
		}
		n.Unlock()
	}
}

// restoredNode makes a node from its journal entry. Called with f and f.jmu
// locked.
func (f *upspinFS) restoredNode(id fuse.NodeID, jn journalNode) *node {
	mode := os.FileMode(jn.mode)
	n := &node{
		f:        f,
		uname:    upspin.PathName(jn.path),
		handles:  make(map[*handle]bool),
		kernelID: id,
		jpath:    jn.path,
		jmode:    jn.mode,
		jmapped:  jn.mapped,
	}
	if strings.Contains(jn.path, "/") {
		n.t = otherNode
		n.stale = jn.mapped
		if p, err := path.Parse(n.uname); err == nil {
			n.user = p.User()
		}
	} else {
		n.t = userNode
		n.user = upspin.UserName(jn.path)
	}
	if !jn.mapped {
		// The node lost its path before the restart, by a rename over it
		// or a delete. Another file may have that path now, so the node
		// must neither look it up nor write back to it.
		n.noWB = true
		n.deleted = true
	}
	now := time.Now()
	n.attr = fuse.Attr{
		Valid:     defaultValid,
		Inode:     jn.inode,
		Mode:      mode,
		Atime:     now,
		Ctime:     now,
		Mtime:     now,
		Crtime:    now,
		Uid:       uint32(f.uid),
		Gid:       uint32(f.gid),
		BlockSize: 4096,
		Nlink:     1,
	}
	n.id = fuse.NodeID(jn.inode)
	return n
}

// refreshStale asks the directory server for the attributes of a restored
// node. Called with n locked.
func (n *node) refreshStale() error {
	const op errors.Op = "refresh"
	_, de, err := n.lookup(n.uname)
	if err == nil && fileType(de) != os.FileMode(n.jmode)&os.ModeType {
		// The path now names a different kind of file. A node keeps its
		// type for its whole life, so this node is gone.
		err = errors.E(errors.NotExist, n.uname)
	}
	if err != nil {
		if !errors.Is(errors.NotExist, err) {
			// Try again on the next refresh.
			return e2e(errors.E(op, err))
		}
		n.stale = false
		n.deleted = true
		n.f.Lock()
		if n.f.nodeMap[n.uname] == n {
			delete(n.f.nodeMap, n.uname)
			n.f.watched.remove(n.uname)
			n.f.setMapped(n, false)
		}
		n.f.Unlock()
		return e2e(errors.E(op, errors.NotExist, n.uname))
	}
	mode := os.FileMode(unixPermissions) | fileType(de)
	if de.IsLink() {
		n.link = upspin.PathName(de.Link)
	}
	size, err := lstatSize(de)
	if err != nil {
		return e2e(errors.E(op, err))
	}
	n.attr.Mode = mode
	n.attr.Size = size
	n.attr.Blocks = (size + 511) / 512
	n.attr.Mtime = de.Time.Go()
	n.attr.Ctime = n.attr.Mtime
	n.seq = de.Sequence
	n.stale = false
	n.refreshTime = time.Now().Add(refreshInterval)
	return nil
}

// fileType returns the type bits of the mode upspinfs gives an entry.
func fileType(de *upspin.DirEntry) os.FileMode {
	switch {
	case de.IsDir():
		return os.ModeDir
	case de.IsLink():
		return os.ModeSymlink
	}
	return 0
}
