// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main // import "upspin.io/cmd/upspinfs"

// The journal keeps the node and handle tables of the FUSE server in a file,
// so that a new upspinfs process can take over a mount after the old one
// died. The kernel still holds node and handle IDs that only the old process
// knew; the journal lets the new process answer for them.
//
// The file is meant to be a memory file (memfd) held open by a supervisor, so
// that it outlives upspinfs but never reaches a disk. Any file works.
//
// Layout: a header of journalHeaderSize bytes, then records. The header holds
// a magic string and the offset of the first live record. Each record is
//
//	u32 payload length | u32 CRC-32C of payload | payload
//
// and every payload states absolute values, so replaying a record twice does
// no harm. Replay stops at the first damaged record, which is where a process
// died in the middle of a write.
//
// Records are only appended. When the log holds many more records than the
// live state needs, the journal appends a snapshot of the live state, moves
// the start offset in the header to it, and frees the old records with a hole
// punched into the file.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"

	"upspin.io/third_party/fuse"
)

const (
	journalMagic      = "upfsjnl1"
	journalHeaderSize = 4096
	journalStartOff   = 8       // Offset of the start pointer in the header.
	maxRecordSize     = 1 << 20 // Larger lengths mean damage.

	// The journal compacts when it holds more than compactMinRecords records
	// and compactFactor times as many records as the live state needs.
	compactMinRecords = 1024
	compactFactor     = 4
)

// Record types.
const (
	recNode    byte = 1 // id, inode, generation, refs, mode, mapped, path
	recForget  byte = 2 // id
	recHandle  byte = 3 // id, node id, flags
	recRelease byte = 4 // id
	recPath    byte = 5 // id, path
	recMapped  byte = 6 // id, mapped
	recGen     byte = 7 // generation
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// journalNode is the saved state of one node the kernel holds.
type journalNode struct {
	inode, gen, refs uint64
	mode             uint32 // os.FileMode bits.
	path             string // Upspin path name; "" for the root.
	mapped           bool   // Lookups of path find this node.
}

// journalHandle is the saved state of one open file handle.
type journalHandle struct {
	node  fuse.NodeID
	flags uint32 // fuse.OpenFlags.
}

// journalState is the live content of a journal.
type journalState struct {
	nodes   map[fuse.NodeID]journalNode
	handles map[fuse.HandleID]journalHandle
	maxGen  uint64 // Highest node generation ever recorded.
}

func newJournalState() journalState {
	return journalState{
		nodes:   make(map[fuse.NodeID]journalNode),
		handles: make(map[fuse.HandleID]journalHandle),
	}
}

// journal appends records to a file. It is not safe for concurrent use; the
// caller serializes all calls.
type journal struct {
	f          *os.File
	start, end int64 // The live log is [start, end).
	records    int   // Records in the live log.
	live       journalState
	err        error // The first write error, if any.
}

// openJournal opens the journal in f. An empty file gets a new journal. For a
// file that holds a journal, it returns the replayed state and drops any
// damaged tail.
func openJournal(f *os.File) (*journal, journalState, error) {
	j := &journal{f: f, live: newJournalState()}
	info, err := f.Stat()
	if err != nil {
		return nil, journalState{}, err
	}
	if info.Size() == 0 {
		var hdr [journalHeaderSize]byte
		copy(hdr[:], journalMagic)
		binary.LittleEndian.PutUint64(hdr[journalStartOff:], journalHeaderSize)
		if _, err := f.WriteAt(hdr[:], 0); err != nil {
			return nil, journalState{}, err
		}
		j.start, j.end = journalHeaderSize, journalHeaderSize
		return j, j.copyState(), nil
	}

	var hdr [journalStartOff + 8]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		// Includes a header shorter than the start offset.
		return nil, journalState{}, fmt.Errorf("journal header: %w", err)
	}
	if string(hdr[:len(journalMagic)]) != journalMagic {
		return nil, journalState{}, errors.New("journal: bad magic")
	}
	j.start = int64(binary.LittleEndian.Uint64(hdr[journalStartOff:]))
	if j.start < journalHeaderSize || j.start > info.Size() {
		return nil, journalState{}, fmt.Errorf("journal: bad start offset %d", j.start)
	}

	off := j.start
	for {
		payload, next, ok := readRecord(f, off)
		if !ok || applyRecord(&j.live, payload) != nil {
			break
		}
		off = next
		j.records++
	}
	j.end = off
	// A process that died after moving the start offset may not have freed
	// the records before it.
	_ = punchHole(f, journalHeaderSize, j.start-journalHeaderSize)
	if off < info.Size() {
		if err := f.Truncate(off); err != nil {
			return nil, journalState{}, err
		}
	}
	return j, j.copyState(), nil
}

// readRecord reads the record at off. It returns false at the end of the log
// or at a damaged record.
func readRecord(f io.ReaderAt, off int64) (payload []byte, next int64, ok bool) {
	var hdr [8]byte
	if _, err := f.ReadAt(hdr[:], off); err != nil {
		return nil, 0, false
	}
	n := binary.LittleEndian.Uint32(hdr[0:])
	if n == 0 || n > maxRecordSize {
		return nil, 0, false
	}
	payload = make([]byte, n)
	if _, err := f.ReadAt(payload, off+8); err != nil {
		return nil, 0, false
	}
	if crc32.Checksum(payload, crcTable) != binary.LittleEndian.Uint32(hdr[4:]) {
		return nil, 0, false
	}
	return payload, off + 8 + int64(n), true
}

// copyState returns a copy of the live state.
func (j *journal) copyState() journalState {
	st := newJournalState()
	for id, n := range j.live.nodes {
		st.nodes[id] = n
	}
	for id, h := range j.live.handles {
		st.handles[id] = h
	}
	st.maxGen = j.live.maxGen
	return st
}

// putNode records a new node or a change to one.
func (j *journal) putNode(id fuse.NodeID, n journalNode) {
	j.append(encodeNode(id, n))
}

// forgetNode records that the kernel forgot a node.
func (j *journal) forgetNode(id fuse.NodeID) {
	j.append(encodeIDs(recForget, uint64(id)))
}

// liveHandle reports whether the journal holds handle id. A nil journal holds
// none.
func (j *journal) liveHandle(id fuse.HandleID) (journalHandle, bool) {
	if j == nil {
		return journalHandle{}, false
	}
	h, ok := j.live.handles[id]
	return h, ok
}

// putHandle records a new handle.
func (j *journal) putHandle(id fuse.HandleID, h journalHandle) {
	j.append(encodeIDs(recHandle, uint64(id), uint64(h.node), uint64(h.flags)))
}

// releaseHandle records that the kernel released a handle.
func (j *journal) releaseHandle(id fuse.HandleID) {
	j.append(encodeIDs(recRelease, uint64(id)))
}

// setPath records that a node has a new path name.
func (j *journal) setPath(id fuse.NodeID, path string) {
	b := encodeIDs(recPath, uint64(id))
	b = binary.AppendUvarint(b, uint64(len(path)))
	j.append(append(b, path...))
}

// setMapped records whether lookups of a node's path find the node.
func (j *journal) setMapped(id fuse.NodeID, mapped bool) {
	j.append(encodeIDs(recMapped, uint64(id), boolToUint(mapped)))
}

func boolToUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func encodeIDs(t byte, ids ...uint64) []byte {
	b := []byte{t}
	for _, id := range ids {
		b = binary.AppendUvarint(b, id)
	}
	return b
}

func encodeNode(id fuse.NodeID, n journalNode) []byte {
	b := encodeIDs(recNode, uint64(id), n.inode, n.gen, n.refs, uint64(n.mode), boolToUint(n.mapped))
	b = binary.AppendUvarint(b, uint64(len(n.path)))
	return append(b, n.path...)
}

// append applies the payload to the live state and writes it as a record.
func (j *journal) append(payload []byte) {
	if len(payload) > maxRecordSize {
		// Replay would treat the record as damage and drop the rest.
		j.fail(fmt.Errorf("journal: record of %d bytes is too large", len(payload)))
		return
	}
	if err := applyRecord(&j.live, payload); err != nil {
		// Only a bug in this file can get here.
		panic(err)
	}
	j.write(payload)
	if j.records > compactMinRecords && j.records > compactFactor*j.liveRecords() {
		j.compact()
	}
}

// write appends one record to the file.
func (j *journal) write(payload []byte) {
	j.writeAll(appendRecord(nil, payload), 1)
}

// appendRecord appends the framed record for payload to buf.
func appendRecord(buf, payload []byte) []byte {
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[4:], crc32.Checksum(payload, crcTable))
	buf = append(buf, hdr[:]...)
	return append(buf, payload...)
}

// writeAll appends n framed records to the file in one write. After the
// first error it writes nothing more: the records after a gap would never be
// replayed.
func (j *journal) writeAll(recs []byte, n int) {
	if j.err != nil {
		return
	}
	if _, err := j.f.WriteAt(recs, j.end); err != nil {
		j.fail(err)
		return
	}
	j.end += int64(len(recs))
	j.records += n
}

func (j *journal) fail(err error) {
	if j.err == nil {
		j.err = err
	}
}

// liveRecords is the number of records a snapshot of the live state needs.
func (j *journal) liveRecords() int {
	return 1 + len(j.live.nodes) + len(j.live.handles)
}

// compact writes a snapshot of the live state, makes it the start of the
// log, and frees the space of the old records. A crash at any point leaves a
// journal that replays to the same state: before the header changes, replay
// reads the old records and then the snapshot, which repeats their result.
func (j *journal) compact() {
	if j.err != nil {
		return
	}
	newStart := j.writeSnapshot()
	if j.err != nil {
		return
	}
	j.switchStart(newStart)
}

// writeSnapshot appends records that state the whole live state, in one
// write, and returns the offset of the first one.
func (j *journal) writeSnapshot() int64 {
	newStart := j.end
	buf := appendRecord(nil, encodeIDs(recGen, j.live.maxGen))
	n := 1
	ids := make([]fuse.NodeID, 0, len(j.live.nodes))
	for id := range j.live.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	for _, id := range ids {
		buf = appendRecord(buf, encodeNode(id, j.live.nodes[id]))
		n++
	}
	hids := make([]fuse.HandleID, 0, len(j.live.handles))
	for id := range j.live.handles {
		hids = append(hids, id)
	}
	sort.Slice(hids, func(a, b int) bool { return hids[a] < hids[b] })
	for _, id := range hids {
		h := j.live.handles[id]
		buf = appendRecord(buf, encodeIDs(recHandle, uint64(id), uint64(h.node), uint64(h.flags)))
		n++
	}
	before := j.records
	j.writeAll(buf, n)
	if j.err == nil {
		j.records -= before
	}
	return newStart
}

// switchStart makes the log start at newStart and frees the records before it.
func (j *journal) switchStart(newStart int64) {
	var ptr [8]byte
	binary.LittleEndian.PutUint64(ptr[:], uint64(newStart))
	if _, err := j.f.WriteAt(ptr[:], journalStartOff); err != nil {
		j.fail(err)
		return
	}
	// A failed punch only wastes space, so its error is not kept.
	_ = punchHole(j.f, j.start, newStart-j.start)
	j.start = newStart
}

// applyRecord applies one record payload to st. A damaged record changes
// nothing.
func applyRecord(st *journalState, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("journal: empty record")
	}
	d := decoder{b: payload[1:]}
	var apply func()
	switch payload[0] {
	case recNode:
		id := fuse.NodeID(d.uvarint())
		n := journalNode{inode: d.uvarint(), gen: d.uvarint(), refs: d.uvarint()}
		n.mode = uint32(d.uvarint())
		n.mapped = d.uvarint() != 0
		n.path = d.str()
		apply = func() {
			st.nodes[id] = n
			if n.gen > st.maxGen {
				st.maxGen = n.gen
			}
		}
	case recForget:
		id := fuse.NodeID(d.uvarint())
		apply = func() { delete(st.nodes, id) }
	case recHandle:
		id := fuse.HandleID(d.uvarint())
		h := journalHandle{node: fuse.NodeID(d.uvarint()), flags: uint32(d.uvarint())}
		apply = func() { st.handles[id] = h }
	case recRelease:
		id := fuse.HandleID(d.uvarint())
		apply = func() { delete(st.handles, id) }
	case recPath:
		id := fuse.NodeID(d.uvarint())
		p := d.str()
		apply = func() {
			if n, ok := st.nodes[id]; ok {
				n.path = p
				st.nodes[id] = n
			}
		}
	case recMapped:
		id := fuse.NodeID(d.uvarint())
		mapped := d.uvarint() != 0
		apply = func() {
			if n, ok := st.nodes[id]; ok {
				n.mapped = mapped
				st.nodes[id] = n
			}
		}
	case recGen:
		gen := d.uvarint()
		apply = func() {
			if gen > st.maxGen {
				st.maxGen = gen
			}
		}
	default:
		return fmt.Errorf("journal: unknown record type %d", payload[0])
	}
	if d.err == nil && len(d.b) != 0 {
		d.err = errors.New("journal: trailing bytes in record")
	}
	if d.err != nil {
		return d.err
	}
	apply()
	return nil
}

type decoder struct {
	b   []byte
	err error
}

func (d *decoder) uvarint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.err = errors.New("journal: bad number")
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) str() string {
	n := d.uvarint()
	if d.err != nil {
		return ""
	}
	if n > uint64(len(d.b)) {
		d.err = errors.New("journal: string past the end of the record")
		return ""
	}
	s := string(d.b[:n])
	d.b = d.b[n:]
	return s
}
