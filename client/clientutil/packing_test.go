// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clientutil

import (
	"testing"

	"upspin.io/config"
	"upspin.io/errors"
	_ "upspin.io/pack/ee"
	_ "upspin.io/pack/eeintegrity"
	"upspin.io/upspin"
)

// TestCheckPacking sets config values that name packings. It does not
// flip the packing switch, but it relies on the eepq packing's state being
// whatever the process started with; keep it out of t.Parallel.
func TestCheckPacking(t *testing.T) {
	file := &upspin.DirEntry{Name: "a@b.com/f", SignedName: "a@b.com/f", Packing: upspin.EEPack}
	dir := &upspin.DirEntry{Name: "a@b.com/d", SignedName: "a@b.com/d", Attr: upspin.AttrDirectory, Packing: upspin.EEPack}
	acc := &upspin.DirEntry{Name: "a@b.com/Access", SignedName: "a@b.com/Access", Packing: upspin.EEIntegrityPack}

	// Unset: nothing is required.
	cfg := config.New()
	for _, e := range []*upspin.DirEntry{file, dir, acc} {
		if err := CheckPacking(cfg, e); err != nil {
			t.Errorf("unset: %s: %v", e.Name, err)
		}
	}

	// Required eeintegrity: the ee file is refused, exempt entries pass.
	cfg = config.SetValue(cfg, RequiredPackingKey, "eeintegrity")
	if err := CheckPacking(cfg, file); !errors.Is(errors.Permission, err) {
		t.Errorf("required eeintegrity, ee file: got %v, want Permission", err)
	}
	for _, e := range []*upspin.DirEntry{dir, acc} {
		if err := CheckPacking(cfg, e); err != nil {
			t.Errorf("required eeintegrity: %s: %v", e.Name, err)
		}
	}
	file.Packing = upspin.EEIntegrityPack
	if err := CheckPacking(cfg, file); err != nil {
		t.Errorf("required eeintegrity, eeintegrity file: %v", err)
	}

	// A name that is not a packing fails closed.
	cfg = config.SetValue(config.New(), RequiredPackingKey, "eeintegrty")
	if err := CheckPacking(cfg, file); !errors.Is(errors.Invalid, err) {
		t.Errorf("typo in requirepacking: got %v, want Invalid", err)
	}
	if _, _, err := RequiredPacking(cfg); !errors.Is(errors.Invalid, err) {
		t.Errorf("RequiredPacking with typo: got %v, want Invalid", err)
	}
}
