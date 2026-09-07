// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ee

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"testing"

	"golang.org/x/crypto/hkdf"

	"upspin.io/pack/packutil"
	"upspin.io/upspin"
)

// samplePackdata returns a packdata with two wrapped keys, filled with
// recognizable values. Under EEPQPack the first wrapped key has an ML-KEM
// ciphertext; the second is an all-users wrap and has none.
func samplePackdata(packing upspin.Packing) packdata {
	fill := func(n int, b byte) []byte {
		s := make([]byte, n)
		for i := range s {
			s[i] = b
		}
		return s
	}
	w0 := wrappedKey{
		keyHash:   fill(sha256.Size, 1),
		dkey:      fill(aesKeyLen+gcmTagSize, 2),
		nonce:     fill(gcmStandardNonceSize, 3),
		ephemeral: ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(12345), Y: big.NewInt(67890)},
	}
	if packing == upspin.EEPQPack {
		w0.encap = fill(mlkem.CiphertextSize768, 4)
	}
	w1 := wrappedKey{
		keyHash: fill(sha256.Size, 5),
		dkey:    fill(aesKeyLen, 6),
	}
	return packdata{
		sig:      upspin.Signature{R: big.NewInt(111), S: big.NewInt(222)},
		sig2:     upspin.Signature{R: big.NewInt(333), S: big.NewInt(444)},
		wrap:     []wrappedKey{w0, w1},
		blockSum: fill(sha256.Size, 7),
	}
}

func TestPackdataRoundTrip(t *testing.T) {
	for _, packing := range []upspin.Packing{upspin.EEPack, upspin.EEPQPack} {
		pd := samplePackdata(packing)
		var b []byte
		if err := pd.Marshal(&b, packing); err != nil {
			t.Fatalf("%s: Marshal: %v", packing, err)
		}
		if len(b) > packdataLen(len(pd.wrap), packing) {
			t.Errorf("%s: marshalled %d bytes, more than packdataLen %d", packing, len(b), packdataLen(len(pd.wrap), packing))
		}
		var got packdata
		if err := got.Unmarshal(b, packing); err != nil {
			t.Fatalf("%s: Unmarshal: %v", packing, err)
		}
		if got.sig.R.Cmp(pd.sig.R) != 0 || got.sig.S.Cmp(pd.sig.S) != 0 {
			t.Errorf("%s: sig mismatch", packing)
		}
		if got.sig2.R.Cmp(pd.sig2.R) != 0 || got.sig2.S.Cmp(pd.sig2.S) != 0 {
			t.Errorf("%s: sig2 mismatch", packing)
		}
		if !bytes.Equal(got.blockSum, pd.blockSum) {
			t.Errorf("%s: blockSum mismatch", packing)
		}
		if len(got.wrap) != len(pd.wrap) {
			t.Fatalf("%s: got %d wrapped keys, want %d", packing, len(got.wrap), len(pd.wrap))
		}
		for i, w := range pd.wrap {
			g := got.wrap[i]
			if !bytes.Equal(g.keyHash, w.keyHash) || !bytes.Equal(g.dkey, w.dkey) || !bytes.Equal(g.nonce, w.nonce) {
				t.Errorf("%s: wrap[%d]: keyHash, dkey or nonce mismatch", packing, i)
			}
			wantX, wantY := big.NewInt(0), big.NewInt(0)
			if w.ephemeral.X != nil {
				wantX, wantY = w.ephemeral.X, w.ephemeral.Y
			}
			if g.ephemeral.X.Cmp(wantX) != 0 || g.ephemeral.Y.Cmp(wantY) != 0 {
				t.Errorf("%s: wrap[%d]: ephemeral mismatch", packing, i)
			}
			if !bytes.Equal(g.encap, w.encap) {
				t.Errorf("%s: wrap[%d]: encap mismatch: got %d bytes, want %d", packing, i, len(g.encap), len(w.encap))
			}
		}
	}
}

// TestEEPackWireFormat pins the EEPack encoding to the layout that predates
// EEPQPack, so that stored data stays readable: an encap field is never
// written under EEPack, even if the wrapped key has one.
func TestEEPackWireFormat(t *testing.T) {
	pd := samplePackdata(upspin.EEPQPack) // wrap[0] has an encap field.
	var got []byte
	if err := pd.Marshal(&got, upspin.EEPack); err != nil {
		t.Fatal(err)
	}

	// The original encoding, spelled out.
	want := make([]byte, 4096)
	n := 0
	for _, i := range []*big.Int{pd.sig.R, pd.sig.S, pd.sig2.R, pd.sig2.S} {
		n += packutil.PutBytes(want[n:], i.Bytes())
	}
	n += binary.PutVarint(want[n:], int64(len(pd.wrap)))
	for _, w := range pd.wrap {
		n += packutil.PutBytes(want[n:], w.keyHash)
		n += packutil.PutBytes(want[n:], w.dkey)
		n += packutil.PutBytes(want[n:], w.nonce)
		var x, y []byte
		if w.ephemeral.X != nil {
			x, y = w.ephemeral.X.Bytes(), w.ephemeral.Y.Bytes()
		}
		n += packutil.PutBytes(want[n:], x)
		n += packutil.PutBytes(want[n:], y)
	}
	n += packutil.PutBytes(want[n:], pd.blockSum)
	want = want[:n]

	if !bytes.Equal(got, want) {
		t.Errorf("EEPack encoding changed:\n got %x\nwant %x", got, want)
	}
	// The EEPQPack encoding of the same data is longer by the encap
	// fields: one varint length and the ciphertext, and one empty length.
	var pq []byte
	if err := pd.Marshal(&pq, upspin.EEPQPack); err != nil {
		t.Fatal(err)
	}
	if got, want := len(pq)-len(got), 2+mlkem.CiphertextSize768+1; got != want {
		t.Errorf("EEPQPack encoding is %d bytes longer than EEPack, want %d", got, want)
	}
}

func TestPackdataLen(t *testing.T) {
	for n := 0; n < 4; n++ {
		if got, want := packdataLen(n, upspin.EEPack), 356+n*274; got != want {
			t.Errorf("packdataLen(%d, EEPack) = %d, want %d", n, got, want)
		}
		if got, want := packdataLen(n, upspin.EEPQPack), 356+n*1852; got != want {
			t.Errorf("packdataLen(%d, EEPQPack) = %d, want %d", n, got, want)
		}
	}
}

// TestStrongKey pins the EEPack key derivation to the original formula and
// checks that the EEPQPack derivation depends on every input it binds.
func TestStrongKey(t *testing.T) {
	pd := samplePackdata(upspin.EEPQPack)
	w := pd.wrap[0]
	R := []byte("reader public point R")
	V := []byte("ephemeral public point V")
	S := []byte("shared point S")
	K := []byte("ml-kem shared secret K, 32 bytes")

	// EEPack: HKDF-SHA256(S) with info "packing:keyHash:nonce".
	got, err := strongKey(upspin.EEPack, w, R, V, S, nil)
	if err != nil {
		t.Fatal(err)
	}
	mess := []byte(fmt.Sprintf("%02x:%x:%x", upspin.EEPack, w.keyHash, w.nonce))
	want := make([]byte, aesKeyLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, S, nil, mess), want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("EEPack strongKey changed")
	}

	// EEPQPack: HKDF-SHA256(K || S || V || R || C || label) with the same info.
	pq, err := strongKey(upspin.EEPQPack, w, R, V, S, K)
	if err != nil {
		t.Fatal(err)
	}
	var ikm []byte
	for _, part := range [][]byte{K, S, V, R, w.encap, []byte(eepqLabel)} {
		ikm = binary.BigEndian.AppendUint32(ikm, uint32(len(part)))
		ikm = append(ikm, part...)
	}
	mess = []byte(fmt.Sprintf("%02x:%x:%x", upspin.EEPQPack, w.keyHash, w.nonce))
	wantPQ := make([]byte, aesKeyLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, mess), wantPQ); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pq, wantPQ) {
		t.Errorf("EEPQPack strongKey changed")
	}
	if bytes.Equal(pq, want) {
		t.Errorf("EEPQPack strongKey equals EEPack strongKey")
	}

	// Each bound input changes the result.
	variants := map[string]func() ([]byte, error){
		"K": func() ([]byte, error) {
			return strongKey(upspin.EEPQPack, w, R, V, S, []byte("another ml-kem secret, 32 bytes!"))
		},
		"S": func() ([]byte, error) { return strongKey(upspin.EEPQPack, w, R, V, []byte("other shared point"), K) },
		"V": func() ([]byte, error) { return strongKey(upspin.EEPQPack, w, R, []byte("other ephemeral"), S, K) },
		"R": func() ([]byte, error) { return strongKey(upspin.EEPQPack, w, []byte("other reader"), V, S, K) },
		"C": func() ([]byte, error) {
			w2 := w
			w2.encap = append([]byte(nil), w.encap...)
			w2.encap[0] ^= 1
			return strongKey(upspin.EEPQPack, w2, R, V, S, K)
		},
		"keyHash": func() ([]byte, error) {
			w2 := w
			w2.keyHash = append([]byte(nil), w.keyHash...)
			w2.keyHash[0] ^= 1
			return strongKey(upspin.EEPQPack, w2, R, V, S, K)
		},
		"nonce": func() ([]byte, error) {
			w2 := w
			w2.nonce = append([]byte(nil), w.nonce...)
			w2.nonce[0] ^= 1
			return strongKey(upspin.EEPQPack, w2, R, V, S, K)
		},
	}
	for name, f := range variants {
		other, err := f()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(pq, other) {
			t.Errorf("EEPQPack strongKey ignores %s", name)
		}
	}
	if _, err := strongKey(upspin.PlainPack, w, R, V, S, K); err == nil {
		t.Errorf("strongKey accepted PlainPack")
	}
}

// TestUnmarshalAllocation checks that a hostile packdata cannot make the
// parser allocate much more than its own size: a packdata claiming the
// most wrapped keys the count guard permits, followed by garbage, must
// allocate less than 64 times its length before it is rejected.
func TestUnmarshalAllocation(t *testing.T) {
	for _, packing := range []upspin.Packing{upspin.EEPack, upspin.EEPQPack} {
		const size = 64 * 1024
		pd := samplePackdata(packing)
		pd.wrap = nil
		var head []byte
		if err := pd.Marshal(&head, packing); err != nil {
			t.Fatal(err)
		}
		// Keep the signatures, replace the count and everything after it.
		n := 0
		buf := make([]byte, marshalBufLen)
		for i := 0; i < 4; i++ {
			k, err := packutil.GetBytes(&buf, head[n:])
			if err != nil {
				t.Fatal(err)
			}
			n += k
		}
		b := make([]byte, size)
		copy(b, head[:n])
		count := (size - n - binary.MaxVarintLen64) / minWrappedKeyLen
		n += binary.PutVarint(b[n:], int64(count))
		for i := n; i < size; i++ {
			b[i] = 0x01 // each field claims length -1, which is malformed
		}

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		var got packdata
		err := got.Unmarshal(b, packing)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Errorf("%s: hostile packdata was accepted", packing)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64*size {
			t.Errorf("%s: Unmarshal of %d hostile bytes allocated %d bytes, more than 64 times the input", packing, size, alloc)
		}
	}
}

// TestMarshalPoint checks that marshalPoint agrees with elliptic.Marshal on
// a valid point, does not panic on an off-curve point, and refuses a
// coordinate that does not fit the field instead of substituting a value.
func TestMarshalPoint(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		got, err := marshalPoint(curve, k.X, k.Y)
		if err != nil {
			t.Fatal(err)
		}
		want := elliptic.Marshal(curve, k.X, k.Y)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: marshalPoint differs from elliptic.Marshal", curve.Params().Name)
		}
		off, err := marshalPoint(curve, big.NewInt(12345), big.NewInt(67890))
		if err != nil || len(off) != len(want) {
			t.Errorf("%s: marshalPoint of off-curve point: %v, %d bytes", curve.Params().Name, err, len(off))
		}
		huge := new(big.Int).Lsh(big.NewInt(1), 1000)
		if _, err := marshalPoint(curve, huge, huge); err == nil {
			t.Errorf("%s: marshalPoint accepted an oversized coordinate", curve.Params().Name)
		}
		if _, err := marshalPoint(curve, big.NewInt(-1), big.NewInt(1)); err == nil {
			t.Errorf("%s: marshalPoint accepted a negative coordinate", curve.Params().Name)
		}
	}
}

// TestUnmarshalMalformed checks that malformed packdata is rejected
// without panicking. Packdata comes from the directory server and must be
// treated as untrusted input.
func TestUnmarshalMalformed(t *testing.T) {
	for _, packing := range []upspin.Packing{upspin.EEPack, upspin.EEPQPack} {
		pd := samplePackdata(packing)
		var good []byte
		if err := pd.Marshal(&good, packing); err != nil {
			t.Fatal(err)
		}
		cases := map[string][]byte{
			"empty":          {},
			"one byte":       {0x01},
			"truncated":      good[:len(good)/2],
			"trailing":       append(append([]byte(nil), good...), 0),
			"huge length":    append([]byte{0xfe, 0xff, 0xff, 0xff, 0x0f}, good[3:]...),
			"negative count": patchCount(good, 0x7f), // zigzag varint -64
			"large count":    patchCount(good, 0x7e), // 63, more than remain
			"negative len":   {0x01, 0x00},
			"other packing":  good,
		}
		for name, b := range cases {
			p := packing
			if name == "other packing" {
				p = upspin.EEPack + upspin.EEPQPack - packing
			}
			var got packdata
			err := got.Unmarshal(b, p)
			if err == nil && name != "other packing" {
				t.Errorf("%s: %s: expected error", packing, name)
			}
		}
	}
}

// patchCount returns a copy of a marshalled packdata with the wrapped key
// count byte, which follows the four signature fields, replaced.
func patchCount(good []byte, count byte) []byte {
	b := append([]byte(nil), good...)
	n := 0
	buf := make([]byte, marshalBufLen)
	for i := 0; i < 4; i++ {
		k, err := packutil.GetBytes(&buf, b[n:])
		if err != nil {
			panic(err)
		}
		n += k
	}
	b[n] = count
	return b
}

func FuzzUnmarshal(f *testing.F) {
	for _, packing := range []upspin.Packing{upspin.EEPack, upspin.EEPQPack} {
		pd := samplePackdata(packing)
		var b []byte
		if err := pd.Marshal(&b, packing); err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		var pd packdata
		pd.Unmarshal(b, upspin.EEPack)
		pd.Unmarshal(b, upspin.EEPQPack)
	})
}
