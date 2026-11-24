// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package storecache

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"upspin.io/bind"
	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/store/inprocess"
	"upspin.io/upspin"
)

// flakyStore is a store behind a proxy (https://github.com/filmil/upspin/issues/139):
// a Put of more than limit bytes fails as the RPC client reports a proxy's
// "413 Request Entity Too Large", and the next transient Puts fail with a
// "503 Service Temporarily Unavailable". All its connections share one state.
type flakyStore struct {
	upspin.StoreServer
	st *flakyState
}

type flakyState struct {
	mu        sync.Mutex
	limit     int // Puts of more bytes than this are rejected with a 413.
	transient int // this many next Puts fail with a 503.
}

func (s *flakyStore) Dial(cfg upspin.Config, e upspin.Endpoint) (upspin.Service, error) {
	inner, err := s.StoreServer.Dial(cfg, e)
	if err != nil {
		return nil, err
	}
	return &flakyStore{StoreServer: inner.(upspin.StoreServer), st: s.st}, nil
}

func (s *flakyStore) Put(data []byte) (*upspin.Refdata, error) {
	s.st.mu.Lock()
	limit := s.st.limit
	transient := s.st.transient > 0
	if transient {
		s.st.transient--
	}
	s.st.mu.Unlock()
	if transient {
		return nil, errors.E(errors.Op("rpc.Invoke"), errors.IO,
			errors.Errorf("503 Service Temporarily Unavailable: <html>nginx</html>"))
	}
	if limit > 0 && len(data) > limit {
		return nil, errors.E(errors.Op("rpc.Invoke"), errors.IO,
			errors.Errorf("413 Request Entity Too Large: <html><head><title>413 Request Entity Too Large</title></head></html>"))
	}
	return s.StoreServer.Put(data)
}

const limit = 1000

var testState = &flakyState{}

func init() {
	// The bind registry is global: one store for the package's tests,
	// whose behavior each test sets through testState.
	if err := bind.RegisterStoreServer(upspin.InProcess, &flakyStore{StoreServer: inprocess.New(), st: testState}); err != nil {
		panic(err)
	}
}

func setStore(t *testing.T, limit, transient int) {
	testState.mu.Lock()
	testState.limit, testState.transient = limit, transient
	testState.mu.Unlock()
	t.Cleanup(func() { setStore(t, 0, 0) })
}

// unique makes block contents that no earlier run of a test has stored, so
// that a block found in the (process-wide) store was written by this run.
func unique(t *testing.T, tag string, n int) []byte {
	head := fmt.Sprintf("%s %s %d ", t.Name(), tag, time.Now().UnixNano())
	if n < len(head) {
		n = len(head)
	}
	return []byte(head + strings.Repeat("x", n-len(head)))
}

func newTestCache(t *testing.T) (*storeCache, string, upspin.Config, upspin.Endpoint) {
	dir := t.TempDir()
	cfg := config.SetUserName(config.New(), "user@example.com")
	c, _, err := newCache(cfg, filepath.Join(dir, "storecache"), filepath.Join(dir, "storewritebackqueue"), 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	return c, dir, cfg, upspin.Endpoint{Transport: upspin.InProcess}
}

// flushAllWithin flushes every location at once, and fails the test if
// that takes longer than d: a stalled writeback queue makes flush wait for
// minutes.
func flushAllWithin(t *testing.T, c *storeCache, locs []upspin.Location, d time.Duration) {
	t.Helper()
	var wg sync.WaitGroup
	for _, loc := range locs {
		wg.Add(1)
		go func(loc upspin.Location) {
			defer wg.Done()
			c.wbq.flush(loc)
		}(loc)
	}
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("flushes did not finish within %s: the writeback queue is stalled", d)
	}
}

func inStore(t *testing.T, cfg upspin.Config, e upspin.Endpoint, ref upspin.Reference) bool {
	store, err := bind.StoreServer(cfg, e)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = store.Get(ref)
	return err == nil
}

// A block the store rejects permanently is set aside, and the blocks queued
// behind it are still written back.
func TestPermanentRejectionDoesNotStall(t *testing.T) {
	setStore(t, limit, 0)
	c, dir, cfg, e := newTestCache(t)
	failedBefore := writebackFailed.Value()

	big := unique(t, "big", 2*limit)
	bigRef, err := c.put(cfg, big, e)
	if err != nil {
		t.Fatal(err)
	}
	// Queued behind the big block before anything is flushed.
	var small []upspin.Reference
	for i := 0; i < 5; i++ {
		ref, err := c.put(cfg, unique(t, fmt.Sprintf("small%d", i), 10), e)
		if err != nil {
			t.Fatal(err)
		}
		small = append(small, ref)
	}
	bigLoc := upspin.Location{Reference: bigRef, Endpoint: e}
	locs := []upspin.Location{bigLoc, bigLoc} // two flushers wait on it
	for _, ref := range small {
		locs = append(locs, upspin.Location{Reference: ref, Endpoint: e})
	}
	flushAllWithin(t, c, locs, 10*time.Second)

	for _, ref := range small {
		if !inStore(t, cfg, e, ref) {
			t.Errorf("small block %s was not written back", ref)
		}
	}
	if inStore(t, cfg, e, bigRef) {
		t.Errorf("the rejected block %s is in the store", bigRef)
	}

	// The rejected block is kept, unchanged and with the reason, where it
	// is not retried, and it is counted.
	rel := c.cachePath(bigRef, e)
	failed := filepath.Join(dir, failedDirName, rel)
	if kept, err := os.ReadFile(failed); err != nil {
		t.Errorf("the rejected block was not set aside: %s", err)
	} else if !bytes.Equal(kept, big) {
		t.Errorf("the block set aside differs from the one written")
	}
	if reason, err := os.ReadFile(failed + failedReasonSuffix); err != nil {
		t.Errorf("no reason recorded: %s", err)
	} else if !strings.Contains(string(reason), "413") {
		t.Errorf("the recorded reason %q does not name the 413", reason)
	}
	if _, err := os.Stat(c.absWritebackPath(rel)); !os.IsNotExist(err) {
		t.Errorf("the rejected block is still queued for writeback: %v", err)
	}
	if got := writebackFailed.Value() - failedBefore; got != 1 {
		t.Errorf("storecache-writeback-failed went up by %d, want 1", got)
	}
}

// After transient failures, the queue retries until the store accepts the
// blocks. Before the fix a failed retry scheduled no further one, and the
// queue stopped for good.
func TestTransientFailuresAreRetried(t *testing.T) {
	old := retryInterval
	retryInterval = 20 * time.Millisecond
	t.Cleanup(func() { retryInterval = old })
	// The first Put fails, then the probe sent after retryInterval fails
	// too, then the store recovers.
	setStore(t, 0, 2)
	c, _, cfg, e := newTestCache(t)

	var locs []upspin.Location
	var refs []upspin.Reference
	for i := 0; i < 3; i++ {
		ref, err := c.put(cfg, unique(t, fmt.Sprintf("b%d", i), 10), e)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
		locs = append(locs, upspin.Location{Reference: ref, Endpoint: e})
	}
	flushAllWithin(t, c, locs, 10*time.Second)
	for _, ref := range refs {
		if !inStore(t, cfg, e, ref) {
			t.Errorf("block %s was not written back after the store recovered", ref)
		}
	}
}

func TestIsPermanent(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		// Too large, under each of the status's names, raw or wrapped.
		{errors.E(errors.IO, errors.Errorf("413 Request Entity Too Large: <html>")), true},
		{errors.E(errors.IO, errors.Errorf("413 Payload Too Large: x")), true},
		{errors.E(errors.Op("store/remote.Put"), errors.E(errors.IO, errors.Errorf("413 Content Too Large: x"))), true},
		{errors.Errorf("413 Request Entity Too Large"), true},
		// The store found the block invalid.
		{errors.E(errors.Invalid, errors.Str("bad block")), true},
		// Retried: a proxy can return these for a while.
		{errors.E(errors.IO, errors.Errorf("404 Not Found: no such route")), false},
		{errors.E(errors.IO, errors.Errorf("401 Unauthorized: x")), false},
		{errors.E(errors.IO, errors.Errorf("403 Forbidden: x")), false},
		{errors.E(errors.IO, errors.Errorf("503 Service Temporarily Unavailable: <html>")), false},
		{errors.E(errors.IO, errors.Errorf("429 Too Many Requests: slow down")), false},
		{errors.E(errors.IO, errors.Errorf("408 Request Timeout: idle")), false},
		{errors.E(errors.IO, errors.Errorf("400 Bad Request: x")), false},
		{errors.E(errors.IO, errors.Str("dial tcp: connection refused")), false},
		// "413" inside a reference or a body is not the status.
		{errors.E(errors.IO, errors.Str("DC413EB8: i/o timeout")), false},
		{errors.E(errors.IO, errors.Errorf("502 Bad Gateway: upstream said 413 Request Entity Too Large")), false},
	} {
		if got := isPermanent(tc.err); got != tc.want {
			t.Errorf("isPermanent(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
