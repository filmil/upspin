// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package storage_test

import (
	"reflect"
	"testing"

	"upspin.io/cloud/storage"
	"upspin.io/cloud/storage/storagetest"
	"upspin.io/errors"
)

func TestRegister(t *testing.T) {
	err := storage.Register("dummy", storagetest.DummyStorage)
	if err != nil {
		t.Fatal(err)
	}
	err = storage.Register("dummy", storagetest.DummyStorage)
	if err == nil {
		t.Fatalf("Duplicate registration should fail.")
	}
	s, err := storage.Dial("dummy", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("Expected non-nil.")
	}
}

type dialingStorage struct {
	t            *testing.T
	expectedOpts storage.Opts
}

func (d *dialingStorage) new(opts *storage.Opts) (storage.Storage, error) {
	if len(opts.Opts) != len(d.expectedOpts.Opts) {
		d.t.Fatalf("Expected %d key-value pairs, got %d", len(d.expectedOpts.Opts), len(opts.Opts))
	}
	if !reflect.DeepEqual(opts.Opts, d.expectedOpts.Opts) {
		d.t.Errorf("key-value pairs mismatch. Expected %v got %v", d.expectedOpts.Opts, opts.Opts)
	}
	return nil, errors.Str("dummy error so we know this was called")
}

func TestDial(t *testing.T) {
	d := dialingStorage{t, storage.Opts{
		Opts: map[string]string{"key1": "val1", "key2": "val2", "key3": "val3"},
	}}
	err := storage.Register("dialTest", d.new)
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.Dial("dialTest",
		storage.WithKeyValue("key1", "val1"),
		storage.WithOptions("key2=val2,key3=val3"))
	if err == nil {
		t.Fatal("Expected a particular error")
	}
	if err.Error() != "dummy error so we know this was called" {
		t.Fatal(err)
	}
}

// wrapped is a Storage that Instrument returned.
type wrapped struct{ storage.Storage }

func TestDialInstrument(t *testing.T) {
	const name = "dummy-instrument"
	if err := storage.Register(name, storagetest.DummyStorage); err != nil && !errors.Is(errors.Exist, err) {
		t.Fatal(err)
	}
	var got string
	storage.Instrument = func(backend string, s storage.Storage) storage.Storage {
		got = backend
		return wrapped{s}
	}
	defer func() { storage.Instrument = nil }()
	s, err := storage.Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(wrapped); !ok || got != name {
		t.Errorf("Dial returned %T after Instrument(%q); want the wrapper, for %q", s, got, name)
	}

	// A backend that fails to start is not instrumented.
	const failing = "failing-instrument"
	if err := storage.Register(failing, func(*storage.Opts) (storage.Storage, error) {
		return nil, errors.Str("no backend")
	}); err != nil && !errors.Is(errors.Exist, err) {
		t.Fatal(err)
	}
	got = ""
	if _, err := storage.Dial(failing); err == nil || got != "" {
		t.Errorf("Dial of a failing backend = %v, Instrument called for %q; want an error and no call", err, got)
	}
}
