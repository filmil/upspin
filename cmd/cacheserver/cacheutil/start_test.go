// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cacheutil

import (
	"flag"
	"strings"
	"testing"

	"upspin.io/flags"
)

// eepqArgs returns the arguments in args that set -eepq, in any form.
func eepqArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "-eepq" || strings.HasPrefix(a, "-eepq=") {
			out = append(out, a)
		}
	}
	return out
}

// TestCacheserverArgsEEPQ checks the arguments cacheserverArgs builds for a
// cacheserver: -eepq=true when this process has -eepq set, and no -eepq
// otherwise. The log level always comes first.
func TestCacheserverArgsEEPQ(t *testing.T) {
	if flag.Lookup("eepq") == nil {
		flags.Register("eepq")
	}
	was := flag.Lookup("eepq").Value.String()
	t.Cleanup(func() {
		if err := flag.Set("eepq", was); err != nil {
			t.Errorf("restoring -eepq: %v", err)
		}
	})

	if err := flag.Set("eepq", "false"); err != nil {
		t.Fatal(err)
	}
	args := cacheserverArgs()
	if !strings.HasPrefix(args[0], "-log=") {
		t.Errorf("cacheserverArgs()[0] = %q, want -log=...", args[0])
	}
	if got := eepqArgs(args); len(got) != 0 {
		t.Errorf("cacheserverArgs without -eepq has %q, want none", got)
	}

	if err := flag.Set("eepq", "true"); err != nil {
		t.Fatal(err)
	}
	if got := eepqArgs(cacheserverArgs()); len(got) != 1 || got[0] != "-eepq=true" {
		t.Errorf("cacheserverArgs with -eepq has %q, want [-eepq=true]", got)
	}
}
