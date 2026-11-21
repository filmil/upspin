// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"upspin.io/cloud/https"
	"upspin.io/cloud/storage"
	"upspin.io/dir/server/serverlog"
	"upspin.io/errors"
	"upspin.io/serverutil/perm"
	"upspin.io/upspin"
)

// fakeStorage is a Storage in memory; fakeLister is also a Lister.
type fakeStorage struct {
	data map[string][]byte
}

func (f *fakeStorage) LinkBase() (string, error) { return "", upspin.ErrNotSupported }
func (f *fakeStorage) Download(ref string) ([]byte, error) {
	b, ok := f.data[ref]
	if !ok {
		return nil, errors.E(errors.NotExist, errors.Str(ref))
	}
	return b, nil
}
func (f *fakeStorage) Put(ref string, b []byte) error { f.data[ref] = b; return nil }
func (f *fakeStorage) Delete(ref string) error        { delete(f.data, ref); return nil }

type fakeLister struct{ fakeStorage }

func (f *fakeLister) List(string) ([]upspin.ListRefsItem, string, error) { return nil, "", nil }

func TestServerMetrics(t *testing.T) {
	base := listen(t)
	https.OnListening()
	if storage.Instrument == nil || serverlog.RootSaveObserver == nil || serverlog.RootRestoreObserver == nil || perm.WritersObserver == nil {
		t.Fatal("serve did not set the server hooks")
	}
	// Label values of their own, so that the counts hold however often
	// the test runs.
	backend := fmt.Sprintf("fake%d", time.Now().UnixNano())

	s := storage.Instrument(backend, &fakeStorage{data: map[string][]byte{}})
	if _, ok := s.(storage.Lister); ok {
		t.Error("a wrapped Storage without List is a Lister")
	}
	if err := s.Put("a", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Download("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Download("missing"); err == nil {
		t.Fatal("Download of a missing ref: expected an error")
	}
	l := storage.Instrument(backend+"l", &fakeLister{fakeStorage{data: map[string][]byte{}}})
	ls, ok := l.(storage.Lister)
	if !ok {
		t.Fatal("a wrapped Lister lost the Lister interface")
	}
	if _, _, err := ls.List(""); err != nil {
		t.Fatal(err)
	}

	serverlog.RootSaveObserver(nil)
	serverlog.RootSaveObserver(errors.E(errors.IO, errors.Str("drive down")))
	serverlog.RootRestoreObserver("restored")

	_, body := get(t, base, "/metrics")
	for _, want := range []string{
		`upspin_storage_requests_total{backend="` + backend + `",op="put",result="ok"} 1`,
		`upspin_storage_requests_total{backend="` + backend + `",op="download",result="ok"} 1`,
		`upspin_storage_requests_total{backend="` + backend + `",op="download",result="not_exist"} 1`,
		`upspin_storage_requests_total{backend="` + backend + `l",op="list",result="ok"} 1`,
		`upspin_storage_bytes_total{backend="` + backend + `",op="put"} 5`,
		`upspin_storage_bytes_total{backend="` + backend + `",op="download"} 5`,
		`upspin_dir_root_backups_total{result="ok"}`,
		`upspin_dir_root_backups_total{result="io"}`,
		`upspin_dir_root_backup_last_success_timestamp_seconds `,
		`upspin_dir_root_restores_total{result="restored"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics does not contain %q", want)
		}
	}
}

func TestWritersHealth(t *testing.T) {
	base := listen(t)
	https.OnListening()
	t.Cleanup(func() {
		writersMu.Lock()
		writers = map[upspin.PathName]int{}
		writersMu.Unlock()
	})
	group := upspin.PathName(fmt.Sprintf("srv%d@example.com/Group/Writers", time.Now().UnixNano()))

	perm.WritersObserver(group, 4)
	if code, _ := get(t, base, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz with 4 writers = %d, want 200", code)
	}
	_, body := get(t, base, "/metrics")
	if want := `upspin_writers{group="` + string(group) + `"} 4`; !strings.Contains(body, want) {
		t.Errorf("/metrics does not contain %q", want)
	}

	perm.WritersObserver(group, -1)
	code, body := get(t, base, "/healthz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "writers: "+string(group)+" missing: every user may write") {
		t.Errorf("/healthz with the Writers file missing = %d %q", code, body)
	}

	perm.WritersObserver(group, 2)
	if code, _ := get(t, base, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz after the Writers file is back = %d, want 200", code)
	}
}
