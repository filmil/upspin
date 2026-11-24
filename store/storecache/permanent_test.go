// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package storecache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"upspin.io/bind"
	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/store/inprocess"
	"upspin.io/upspin"
)

// limitStore is a store behind a proxy with a request body limit: a Put of
// more than limit bytes fails the way the RPC client reports a proxy's
// "413 Request Entity Too Large" (https://github.com/filmil/upspin/issues/139).
type limitStore struct {
	upspin.StoreServer
	limit int
}

func (s *limitStore) Dial(cfg upspin.Config, e upspin.Endpoint) (upspin.Service, error) {
	inner, err := s.StoreServer.Dial(cfg, e)
	if err != nil {
		return nil, err
	}
	return &limitStore{StoreServer: inner.(upspin.StoreServer), limit: s.limit}, nil
}

func (s *limitStore) Put(data []byte) (*upspin.Refdata, error) {
	if len(data) > s.limit {
		return nil, errors.E(errors.Op("rpc.Invoke"), errors.IO,
			errors.Errorf("413 Request Entity Too Large: <html><head><title>413 Request Entity Too Large</title></head></html>"))
	}
	return s.StoreServer.Put(data)
}

const limit = 1000

var testStore = &limitStore{StoreServer: inprocess.New(), limit: limit}

func init() {
	if err := bind.RegisterStoreServer(upspin.InProcess, testStore); err != nil {
		panic(err)
	}
}

// flushWithin flushes loc, and fails the test if that takes longer than d:
// a stalled writeback queue makes flush wait for minutes.
func flushWithin(t *testing.T, c *storeCache, loc upspin.Location, d time.Duration) {
	t.Helper()
	done := make(chan bool)
	go func() {
		c.wbq.flush(loc)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("flush of %s did not finish within %s: the writeback queue is stalled", loc.Reference, d)
	}
}

// A block the store rejects permanently is failed and set aside, and the
// blocks queued after it are still written back.
func TestPermanentRejectionDoesNotStall(t *testing.T) {
	dir := t.TempDir()
	cfg := config.SetUserName(config.New(), "user@example.com")
	e := upspin.Endpoint{Transport: upspin.InProcess}
	c, _, err := newCache(cfg, filepath.Join(dir, "storecache"), filepath.Join(dir, "storewritebackqueue"), 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}

	big := []byte(strings.Repeat("b", 2*limit))
	bigRef, err := c.put(cfg, big, e)
	if err != nil {
		t.Fatal(err)
	}
	// The flush of the rejected block returns rather than waiting forever.
	flushWithin(t, c, upspin.Location{Reference: bigRef, Endpoint: e}, 10*time.Second)

	var small []upspin.Reference
	for i := 0; i < 5; i++ {
		ref, err := c.put(cfg, []byte(strings.Repeat("s", 10+i)), e)
		if err != nil {
			t.Fatal(err)
		}
		small = append(small, ref)
	}
	for _, ref := range small {
		flushWithin(t, c, upspin.Location{Reference: ref, Endpoint: e}, 10*time.Second)
	}

	store, err := bind.StoreServer(cfg, e)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range small {
		if _, _, _, err := store.Get(ref); err != nil {
			t.Errorf("small block %s was not written back: %s", ref, err)
		}
	}
	if _, _, _, err := store.Get(bigRef); err == nil {
		t.Errorf("the rejected block %s is in the store", bigRef)
	}

	// The rejected block is kept, with the reason, where it is not retried.
	rel := c.cachePath(bigRef, e)
	failed := filepath.Join(dir, failedDirName, rel)
	if _, err := os.Stat(failed); err != nil {
		t.Errorf("the rejected block was not set aside: %s", err)
	}
	reason, err := os.ReadFile(failed + failedReasonSuffix)
	if err != nil {
		t.Errorf("no reason recorded: %s", err)
	} else if !strings.Contains(string(reason), "413") {
		t.Errorf("the recorded reason %q does not name the 413", reason)
	}
	if _, err := os.Stat(c.absWritebackPath(rel)); !os.IsNotExist(err) {
		t.Errorf("the rejected block is still queued for writeback: %v", err)
	}
}

func TestIsPermanent(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.E(errors.IO, errors.Errorf("413 Request Entity Too Large: <html>")), true},
		{errors.E(errors.IO, errors.Errorf("404 Not Found: no such route")), true},
		{errors.E(errors.Invalid, errors.Str("block too large")), true},
		// Transient, or treated as such: retried.
		{errors.E(errors.IO, errors.Errorf("503 Service Temporarily Unavailable: <html>")), false},
		{errors.E(errors.IO, errors.Errorf("429 Too Many Requests: slow down")), false},
		{errors.E(errors.IO, errors.Errorf("408 Request Timeout: idle")), false},
		{errors.E(errors.IO, errors.Errorf("400 Bad Request: x")), false},
		{errors.E(errors.IO, errors.Str("dial tcp: connection refused")), false},
		// A digit run inside a reference is not a status.
		{errors.E(errors.IO, errors.Str("ref 4130ABC: i/o timeout")), false},
	} {
		if got := isPermanent(tc.err); got != tc.want {
			t.Errorf("isPermanent(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
