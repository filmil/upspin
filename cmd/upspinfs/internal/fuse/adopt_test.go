// SPDX-License-Identifier: Apache-2.0

package fuse_test

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"upspin.io/cmd/upspinfs/internal/fuse"
)

func TestAdoptRejectsBadInput(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	if _, err := fuse.Adopt(nil, fuse.Protocol{Major: 7, Minor: 12}); err == nil {
		t.Error("Adopt accepted a nil device")
	}
	var old *fuse.OldVersionError
	if _, err := fuse.Adopt(r, fuse.Protocol{Major: 7, Minor: 7}); !errors.As(err, &old) {
		t.Errorf("Adopt with an old protocol: got error %v, want OldVersionError", err)
	}
	if _, err := fuse.Adopt(r, fuse.Protocol{Major: 7, Minor: 13}); err == nil {
		t.Error("Adopt accepted a protocol newer than the library")
	}
}

// TestAdoptReadsWithoutInit checks that the first message on an adopted
// descriptor is parsed as an ordinary request. A Conn made by Mount would
// insist on INIT.
func TestAdoptReadsWithoutInit(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	proto := fuse.Protocol{Major: 7, Minor: 12}
	c, err := fuse.Adopt(r, proto)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	select {
	case <-c.Ready:
	default:
		t.Error("Ready is not closed")
	}
	if c.MountError != nil {
		t.Errorf("MountError = %v", c.MountError)
	}
	if got := c.Protocol(); got != proto {
		t.Errorf("Protocol = %v, want %v", got, proto)
	}
	if c.File() != r {
		t.Error("File does not return the adopted descriptor")
	}

	// A GETATTR message: the 40 byte header, then 16 bytes of arguments.
	const (
		headerSize = 40
		argSize    = 16
		opGetattr  = 3
		unique     = 42
		nodeID     = 7
	)
	msg := make([]byte, headerSize+argSize)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.NativeEndian.PutUint32(msg[4:], opGetattr)
	binary.NativeEndian.PutUint64(msg[8:], unique)
	binary.NativeEndian.PutUint64(msg[16:], nodeID)
	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}

	req, err := c.ReadRequest()
	if err != nil {
		t.Fatal(err)
	}
	getattr, ok := req.(*fuse.GetattrRequest)
	if !ok {
		t.Fatalf("got request %T, want *fuse.GetattrRequest", req)
	}
	if got := getattr.Hdr().Node; got != nodeID {
		t.Errorf("Node = %v, want %v", got, nodeID)
	}
	if got := getattr.Hdr().ID; got != unique {
		t.Errorf("ID = %v, want %v", got, unique)
	}
}
