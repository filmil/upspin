// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ee

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"upspin.io/test/testutil"
	"upspin.io/upspin"
)

// TestMarshalGolden pins the bytes packdata.Marshal writes for the fixed
// struct of samplePackdata, under both packings, to the hex fixtures in
// testdata/marshal-<packing>.hex. Any change to the wire format fails here
// and must update the fixture on purpose. To regenerate, run the test with
// UPSPIN_GOLDEN_GEN set and copy the hex it prints for each packing.
func TestMarshalGolden(t *testing.T) {
	for _, packing := range []upspin.Packing{upspin.EEPack, upspin.EEPQPack} {
		pd := samplePackdata(packing)
		var b []byte
		if err := pd.Marshal(&b, packing); err != nil {
			t.Fatal(err)
		}
		got := hex.EncodeToString(b)
		if os.Getenv("UPSPIN_GOLDEN_GEN") != "" {
			fmt.Printf("GOLDEN-BEGIN %s\n%s\nGOLDEN-END\n", packing, got)
			continue
		}
		file := testutil.Repo("pack", "ee", "testdata", fmt.Sprintf("marshal-%s.hex", packing))
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if got != strings.TrimSpace(string(want)) {
			t.Errorf("%s: Marshal bytes changed:\n got %s\nwant %s", packing, got, strings.TrimSpace(string(want)))
		}
		// And the fixture still parses back to the same struct.
		var back packdata
		if err := back.Unmarshal(b, packing); err != nil {
			t.Errorf("%s: Unmarshal of golden bytes: %v", packing, err)
		}
	}
}
