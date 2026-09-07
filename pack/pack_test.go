// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pack

import (
	"testing"

	"upspin.io/upspin"
)

// testPacker is a Packer that does nothing but name a packing.
type testPacker struct {
	upspin.Packer
	packing upspin.Packing
}

func (p testPacker) Packing() upspin.Packing { return p.packing }
func (p testPacker) String() string          { return "testpacker" }

// TestSetEnabled checks that a disabled packing stays registered and
// resolvable by Lookup and LookupByName, so that its operations can fail
// with a message that names the switch, while Enabled reports false.
func TestSetEnabled(t *testing.T) {
	const packing upspin.Packing = 7 // in the range reserved for tests
	p := testPacker{packing: packing}
	if err := Register(p); err != nil {
		t.Fatal(err)
	}
	if !Enabled(packing) {
		t.Error("registered packing is not enabled")
	}
	SetEnabled(packing, false)
	if Enabled(packing) {
		t.Error("disabled packing reports enabled")
	}
	if Lookup(packing) == nil || LookupByName("testpacker") == nil {
		t.Error("disabled packing is not resolvable")
	}
	SetEnabled(packing, true)
	if !Enabled(packing) {
		t.Error("re-enabled packing reports disabled")
	}
	if Enabled(upspin.Packing(19)) {
		t.Error("unregistered packing reports enabled")
	}
}
