// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cacheutil

import (
	"flag"
	"slices"
	"testing"

	"upspin.io/flags"
)

// TestCacheserverArgsPassesEEPQ checks that a process started with -eepq
// starts its cacheserver with -eepq too, and one without it does not.
func TestCacheserverArgsPassesEEPQ(t *testing.T) {
	flags.Register("eepq")
	defer flag.Set("eepq", "false")

	if args := cacheserverArgs(); slices.Contains(args, "-eepq=true") {
		t.Errorf("cacheserverArgs without -eepq = %q, want no -eepq", args)
	}
	if err := flag.Set("eepq", "true"); err != nil {
		t.Fatal(err)
	}
	if args := cacheserverArgs(); !slices.Contains(args, "-eepq=true") {
		t.Errorf("cacheserverArgs with -eepq = %q, want -eepq=true", args)
	}
}
