// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"bytes"
	"io"
	"os"

	"upspin.io/upspin"
)

// spool accumulates the contents of a writable File until it is closed.
// Data is held in memory until it grows beyond maxInMemory bytes, at which
// point it is moved to a temporary file on local disk so that a file of any
// size can be written without holding it all in memory.
// The temporary file holds cleartext, with permissions that make it
// readable only by the user, and is removed when the spool is closed.
type spool struct {
	mem  []byte   // Contents while held in memory; nil once spilled to disk.
	file *os.File // Backing file once spilled to disk; nil until then.
	size int64    // Size of the contents.
}

// maxInMemory is the largest size a spool holds in memory before spilling
// to disk. Anything that fits in one block stays in memory.
// It is a variable so tests can reduce it.
var maxInMemory = int64(upspin.BlockSize)

// writeAt writes b at offset off, extending the contents with zeros
// if off is beyond their current end.
func (s *spool) writeAt(b []byte, off int64) (int, error) {
	end := off + int64(len(b))
	if s.file == nil {
		if end <= maxInMemory {
			s.writeMem(b, off, end)
			return len(b), nil
		}
		if err := s.spill(); err != nil {
			return 0, err
		}
	}
	n, err := s.file.WriteAt(b, off)
	if err != nil {
		return n, err
	}
	if end := off + int64(n); end > s.size {
		if n == 0 {
			// An empty write beyond the end still extends the contents
			// with zeros, as it does in memory, but WriteAt does not
			// extend the file, so do it explicitly.
			if err := s.file.Truncate(end); err != nil {
				return 0, err
			}
		}
		s.size = end
	}
	return n, nil
}

// writeMem writes b at off into the in-memory contents, which must
// be able to hold end bytes without exceeding maxInMemory.
func (s *spool) writeMem(b []byte, off, end int64) {
	if end > int64(cap(s.mem)) {
		// Grow the capacity of s.mem but keep length the same.
		nCap := end * 3 / 2
		if nCap > maxInMemory {
			nCap = maxInMemory
		}
		mem := make([]byte, len(s.mem), nCap)
		copy(mem, s.mem)
		s.mem = mem
	}
	// Capacity is OK now. Fix the length if necessary.
	// Any bytes exposed by extending the length are zero, as they
	// have never been written.
	if end > int64(len(s.mem)) {
		s.mem = s.mem[:end]
	}
	copy(s.mem[off:], b)
	s.size = int64(len(s.mem))
}

// spill moves the contents from memory to a temporary file on disk.
func (s *spool) spill() error {
	f, err := os.CreateTemp("", "upspin-file-")
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(s.mem, 0); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	s.file = f
	s.mem = nil
	return nil
}

// reader returns a reader for the contents.
func (s *spool) reader() io.Reader {
	if s.file == nil {
		return bytes.NewReader(s.mem)
	}
	return io.NewSectionReader(s.file, 0, s.size)
}

// close releases the contents and removes the temporary file, if any.
func (s *spool) close() error {
	s.mem = nil
	if s.file == nil {
		return nil
	}
	name := s.file.Name()
	err := s.file.Close()
	if rerr := os.Remove(name); err == nil {
		err = rerr
	}
	s.file = nil
	return err
}
