// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ee

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"upspin.io/test/testutil"
	"upspin.io/upspin"
)

// TestStrongKeyVectors checks strongKey against the known answer vectors
// in testdata/combiner-vectors.json, one per key type. The file spells
// out every input and the derivation, so another implementation can
// check the same vectors. A change to the keying material order, the
// length prefixes or the label fails here even if it is self-consistent.
// ML-KEM itself is not tested; crypto/mlkem runs the FIPS 203 vectors.
func TestStrongKeyVectors(t *testing.T) {
	var doc struct {
		Vectors []struct {
			KeyType, KeyHash, Nonce, Encap, R, V, S, K, Strong string
		}
	}
	b, err := os.ReadFile(testutil.Repo("pack", "ee", "testdata", "combiner-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) != 3 {
		t.Fatalf("got %d vectors, want 3", len(doc.Vectors))
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range doc.Vectors {
		w := wrappedKey{keyHash: unhex(v.KeyHash), nonce: unhex(v.Nonce), encap: unhex(v.Encap)}
		got, err := strongKey(upspin.EEPQPack, w, unhex(v.R), unhex(v.V), unhex(v.S), unhex(v.K))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != v.Strong {
			t.Errorf("%s: combiner vector changed:\n got %x\nwant %s", v.KeyType, got, v.Strong)
		}
	}
}
