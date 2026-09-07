// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package factotum

import (
	"bytes"
	"crypto/elliptic"
	"crypto/mlkem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"upspin.io/errors"
	"upspin.io/upspin"
)

func TestNewFromDir(t *testing.T) {
	const (
		pubKey    = "p256\n86754568856409436056886548963722747418663925733852968840719951502625645703023\n55374006944977701639377273685946154797448684848748065688191847332792959379206\n"
		secKey    = "33732563467898584041325590158539299810645722675081856412396066039103123277092\n"
		newPubKey = "p256\n6640270742675236934700552659758623510932789581985633007789325329362331148012\n68892645101823987570169861213316538980647268870890981023717754447508722389034\n"
		newSecKey = "73412709577437621283953284627141522517131750837511539431619352194608555895350\n"
	)

	cases := []struct {
		dir        string
		ok         bool
		public     upspin.PublicKey
		secret     string
		prevPublic upspin.PublicKey
		prevSecret string
	}{
		// Check that basic key parsing and parsing of archived keys works.
		{"ok", true, pubKey, secKey, "", ""},
		{"ok-archived", true, newPubKey, newSecKey, pubKey, secKey},
		// When we fail to parse the archived keys
		// we should see the current key as the previous key.
		{"bad-archived", true, newPubKey, newSecKey, newPubKey, newSecKey},
		// These should outright fail.
		{"bad", false, "", "", "", ""},
		{"empty", false, "", "", "", ""},
		{"mismatched", false, pubKey, secKey, "", ""},
	}
	for _, c := range cases {
		fi, err := NewFromDir(filepath.Join("testdata", c.dir))
		if err != nil {
			if c.ok {
				t.Errorf("NewFromDir(%q): %v", c.dir, err)
			}
			continue
		}
		if !c.ok {
			t.Errorf("NewFromDir(%q) returned nil error, expected error", c.dir)
			continue
		}
		f := fi.(*factotum)
		if got, want := f.keys[f.current].public, c.public; got != want {
			t.Errorf("NewFromDir(%q): got public key %q, want %q", c.dir, got, want)
		}
		if got, want := f.keys[f.current].private, c.secret; got != want {
			t.Errorf("NewFromDir(%q): got secret key %q, want %q", c.dir, got, want)
		}
		if c.prevPublic == "" {
			if f.current != f.previous {
				t.Errorf("NewFromDir(%q): expected no previous key, got %s", c.dir, f.previous)
			}
			continue
		}
		if got, want := f.keys[f.previous].public, c.prevPublic; got != want {
			t.Errorf("NewFromDir(%q): got previous public key %q, want %q", c.dir, got, want)
		}
		if got, want := f.keys[f.previous].private, c.prevSecret; got != want {
			t.Errorf("NewFromDir(%q): got previous secret key %q, want %q", c.dir, got, want)
		}
	}
}

func TestClean(t *testing.T) {
	f, err := NewFromDir(filepath.Join("testdata", "ok"))
	if err != nil {
		t.Errorf("NewFromDir(testdata/ok): %v", err)
	}
	fi1 := f.(*factotum)
	f, err = NewFromDir(filepath.Join("testdata", "comment"))
	if err != nil {
		t.Errorf("NewFromDir(testdata/comment): %v", err)
	}
	fi2 := f.(*factotum)
	d1 := fi1.keys[fi1.current].ecdsaKeyPair.D
	d2 := fi2.keys[fi2.current].ecdsaKeyPair.D
	if d1.Cmp(d2) != 0 {
		t.Errorf("NewFromDir: comment improperly affected key")
	}

}

func TestSign(t *testing.T) {
	fi, err := NewFromDir(filepath.Join("testdata", "ok"))
	if err != nil {
		t.Errorf("NewFromDir(testdata/ok): %v", err)
	}
	_, err = fi.Sign([]byte("this is too long a string for p256"))
	if err == nil {
		t.Errorf("factotum.Sing(longstring) should have failed")
	}
}

// TestNewFromDirPQ checks that a post-quantum key pair loads.
func TestNewFromDirPQ(t *testing.T) {
	// testdata/pq was made by "keygen -curve p256+mlkem768".
	fi, err := NewFromDir(filepath.Join("testdata", "pq"))
	if err != nil {
		t.Fatalf("NewFromDir(testdata/pq): %v", err)
	}
	f := fi.(*factotum)
	fk := f.keys[f.current]
	if fk.kem == nil {
		t.Fatal("NewFromDir(testdata/pq): no ML-KEM decapsulation key")
	}
	if !strings.HasPrefix(string(fk.public), "p256+mlkem768\n") {
		t.Errorf("NewFromDir(testdata/pq): public key type is %q", strings.SplitN(string(fk.public), "\n", 2)[0])
	}
	if got := len(fk.kem.Encapsulator().Bytes()); got != mlkem.EncapsulationKeySize768 {
		t.Errorf("NewFromDir(testdata/pq): encapsulation key has %d bytes, want %d", got, mlkem.EncapsulationKeySize768)
	}
	if f.current != f.previous {
		t.Errorf("NewFromDir(testdata/pq): expected no previous key")
	}
}

// TestNewFromDirPQArchived checks parsing of secret2.upspinkey records that
// hold post-quantum keys, which have two more lines than classic records.
func TestNewFromDirPQArchived(t *testing.T) {
	// testdata/pq-archived: current key is classic p256; the archive holds
	// a p256+mlkem768 record followed by a p384+mlkem768 record.
	fi, err := NewFromDir(filepath.Join("testdata", "pq-archived"))
	if err != nil {
		t.Fatalf("NewFromDir(testdata/pq-archived): %v", err)
	}
	f := fi.(*factotum)
	if got, want := len(f.keys), 3; got != want {
		t.Fatalf("NewFromDir(testdata/pq-archived): loaded %d keys, want %d", got, want)
	}
	cur := f.keys[f.current]
	if !strings.HasPrefix(string(cur.public), "p256\n") || cur.kem != nil {
		t.Errorf("NewFromDir(testdata/pq-archived): current key should be classic p256")
	}
	prev := f.keys[f.previous]
	if !strings.HasPrefix(string(prev.public), "p384+mlkem768\n") || prev.kem == nil {
		t.Errorf("NewFromDir(testdata/pq-archived): previous key should be p384+mlkem768")
	}
	if strings.Contains(prev.private, "#") || strings.Count(prev.private, "\n") != 2 {
		t.Errorf("NewFromDir(testdata/pq-archived): archived private key not cleaned: %q", prev.private)
	}
	// An archived post-quantum key must still decapsulate, so that data
	// wrapped for it before a rotation stays readable.
	ek, err := ParseEncapsulationKey(prev.public)
	if err != nil {
		t.Fatal(err)
	}
	want, ct := ek.Encapsulate()
	got, err := fi.(Decapsulator).Decapsulate(KeyHash(prev.public), ct)
	if err != nil {
		t.Fatalf("Decapsulate with archived key: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Decapsulate with archived key: shared secret mismatch")
	}
}

func TestDecapsulate(t *testing.T) {
	fi, err := NewFromDir(filepath.Join("testdata", "pq"))
	if err != nil {
		t.Fatalf("NewFromDir(testdata/pq): %v", err)
	}
	pub := fi.PublicKey()
	hash := KeyHash(pub)
	ek, err := ParseEncapsulationKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	want, ct := ek.Encapsulate()
	if got := len(ct); got != mlkem.CiphertextSize768 {
		t.Errorf("ciphertext has %d bytes, want %d", got, mlkem.CiphertextSize768)
	}
	got, err := fi.(Decapsulator).Decapsulate(hash, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Decapsulate: shared secret mismatch")
	}

	// Unknown key hash.
	if _, err := fi.(Decapsulator).Decapsulate([]byte("no such key"), ct); !errors.Is(errors.NotExist, err) {
		t.Errorf("Decapsulate with unknown hash: got %v, want NotExist", err)
	}
	// Ciphertext of the wrong length.
	if _, err := fi.(Decapsulator).Decapsulate(hash, ct[:len(ct)-1]); !errors.Is(errors.Invalid, err) {
		t.Errorf("Decapsulate with short ciphertext: got %v, want Invalid", err)
	}
	// A tampered ciphertext is not an error: ML-KEM rejects implicitly by
	// returning an unrelated secret. Callers must authenticate the result.
	bad := append([]byte(nil), ct...)
	bad[0] ^= 1
	other, err := fi.(Decapsulator).Decapsulate(hash, bad)
	if err != nil {
		t.Fatalf("Decapsulate with tampered ciphertext: %v", err)
	}
	if bytes.Equal(other, want) {
		t.Errorf("Decapsulate with tampered ciphertext returned the real secret")
	}
	// A classic key cannot decapsulate.
	fc, err := NewFromDir(filepath.Join("testdata", "ok"))
	if err != nil {
		t.Fatalf("NewFromDir(testdata/ok): %v", err)
	}
	if _, err := fc.(Decapsulator).Decapsulate(KeyHash(fc.PublicKey()), ct); !errors.Is(errors.Invalid, err) {
		t.Errorf("Decapsulate with classic key: got %v, want Invalid", err)
	}
}

func TestParseKeyType(t *testing.T) {
	cases := []struct {
		name  string
		curve elliptic.Curve
		kem   KEM
		ok    bool
	}{
		{"p256", elliptic.P256(), NoKEM, true},
		{"p384", elliptic.P384(), NoKEM, true},
		{"p521", elliptic.P521(), NoKEM, true},
		{"p256+mlkem768", elliptic.P256(), MLKEM768, true},
		{"p384+mlkem768", elliptic.P384(), MLKEM768, true},
		{"p521+mlkem1024", elliptic.P521(), MLKEM1024, true},
		// Mixed strengths are refused.
		{"p256+mlkem1024", nil, NoKEM, false},
		{"p384+mlkem1024", nil, NoKEM, false},
		{"p521+mlkem768", nil, NoKEM, false},
		{"", nil, NoKEM, false},
		{"p123", nil, NoKEM, false},
		{"p256+", nil, NoKEM, false},
		{"p256+mlkem512", nil, NoKEM, false},
		{"mlkem768", nil, NoKEM, false},
		{"p256+mlkem768+mlkem768", nil, NoKEM, false},
	}
	for _, c := range cases {
		curve, kem, err := ParseKeyType(c.name)
		if (err == nil) != c.ok {
			t.Errorf("ParseKeyType(%q): err %v, want ok=%t", c.name, err, c.ok)
			continue
		}
		if !c.ok {
			if !errors.Is(errors.Invalid, err) {
				t.Errorf("ParseKeyType(%q): got %v, want Invalid", c.name, err)
			}
			continue
		}
		if curve != c.curve || kem != c.kem {
			t.Errorf("ParseKeyType(%q) = %v, %q; want %v, %q", c.name, curve.Params().Name, kem, c.curve.Params().Name, c.kem)
		}
	}
	// Every listed key type parses.
	for _, name := range KeyTypes {
		if _, _, err := ParseKeyType(name); err != nil {
			t.Errorf("ParseKeyType(%q) from KeyTypes: %v", name, err)
		}
	}
}

func TestParseEncapsulationKey(t *testing.T) {
	fi, err := NewFromDir(filepath.Join("testdata", "pq"))
	if err != nil {
		t.Fatalf("NewFromDir(testdata/pq): %v", err)
	}
	pub := fi.PublicKey()
	lines := strings.Split(string(pub), "\n")
	if len(lines) != 5 {
		t.Fatalf("post-quantum public key has %d lines, want 4 plus a terminator", len(lines)-1)
	}

	ek, err := ParseEncapsulationKey(pub)
	if err != nil {
		t.Fatalf("ParseEncapsulationKey: %v", err)
	}
	if got := len(ek.Bytes()); got != mlkem.EncapsulationKeySize768 {
		t.Errorf("encapsulation key has %d bytes, want %d", got, mlkem.EncapsulationKeySize768)
	}
	// ParsePublicKey also accepts the key and returns the ECDSA part.
	if _, err := ParsePublicKey(pub); err != nil {
		t.Errorf("ParsePublicKey(post-quantum key): %v", err)
	}

	// A classic key has no KEM.
	classic := upspin.PublicKey(strings.Join([]string{"p256", lines[1], lines[2]}, "\n") + "\n")
	if _, err := ParseEncapsulationKey(classic); !errors.Is(errors.NotExist, err) {
		t.Errorf("ParseEncapsulationKey(classic key): got %v, want NotExist", err)
	}
	// A post-quantum key type without its fourth line is malformed.
	missing := upspin.PublicKey(strings.Join(lines[:3], "\n") + "\n")
	if _, err := ParseEncapsulationKey(missing); !errors.Is(errors.Invalid, err) {
		t.Errorf("ParseEncapsulationKey(missing line): got %v, want Invalid", err)
	}
	if _, err := ParsePublicKey(missing); !errors.Is(errors.Invalid, err) {
		t.Errorf("ParsePublicKey(missing line): got %v, want Invalid", err)
	}
	// So is one whose fourth line is not an encapsulation key.
	garbage := upspin.PublicKey(strings.Join([]string{lines[0], lines[1], lines[2], "bm90IGEga2V5"}, "\n") + "\n")
	if _, err := ParseEncapsulationKey(garbage); !errors.Is(errors.Invalid, err) {
		t.Errorf("ParseEncapsulationKey(garbage): got %v, want Invalid", err)
	}
}

// TestNewFromKeysPQMismatch checks that the private key must match both
// parts of a post-quantum public key.
func TestNewFromKeysPQMismatch(t *testing.T) {
	read := func(dir, name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pub := read("pq", "public.upspinkey")
	priv := read("pq", "secret.upspinkey")
	if _, err := NewFromKeys(pub, priv, nil); err != nil {
		t.Fatalf("NewFromKeys(pq): %v", err)
	}
	// Only the ECDSA scalar: too few lines for a post-quantum key.
	scalar := priv[:bytes.IndexByte(priv, '\n')+1]
	if _, err := NewFromKeys(pub, scalar, nil); err == nil {
		t.Error("NewFromKeys(pq public, classic private): expected error")
	}
	// The right scalar with another key's ML-KEM seed.
	otherPriv := read("pq-archived", "secret2.upspinkey")
	otherLines := strings.Split(string(otherPriv), "\n")
	// The second archived record is p384+mlkem768; its seed is on line 13
	// (record header, four public lines, D, seed; twice).
	wrongSeed := append(append([]byte(nil), scalar...), []byte(otherLines[13]+"\n")...)
	if _, err := NewFromKeys(pub, wrongSeed, nil); err == nil {
		t.Error("NewFromKeys(pq public, wrong ML-KEM seed): expected error")
	}
}

// TestKeyLengthLimits checks that oversized key material is rejected by a
// length check before any parsing, and that the fixtures fit under the
// limits with room to spare.
func TestKeyLengthLimits(t *testing.T) {
	read := func(dir, name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pub := read("pq", "public.upspinkey")
	priv := read("pq", "secret.upspinkey")
	archive := read("pq-archived", "secret2.upspinkey")
	if len(pub) > MaxPublicKeyLen/2 || len(priv) > MaxPrivateKeyLen/2 || len(archive) > MaxArchiveLen/64 {
		t.Errorf("fixtures too close to the limits: pub %d, priv %d, archive %d", len(pub), len(priv), len(archive))
	}

	// A public key of digits that would cost a big.Int parse is refused
	// by length, and cheaply.
	huge := []byte("p256\n" + strings.Repeat("9", MaxPublicKeyLen) + "\n1\n")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := ParsePublicKey(upspin.PublicKey(huge))
	runtime.ReadMemStats(&after)
	if !errors.Is(errors.Invalid, err) {
		t.Errorf("oversized public key: got %v, want Invalid", err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4*uint64(len(huge)) {
		t.Errorf("oversized public key allocated %d bytes for %d of input", alloc, len(huge))
	}
	if _, err := ParseEncapsulationKey(upspin.PublicKey(huge)); !errors.Is(errors.Invalid, err) {
		t.Errorf("oversized key to ParseEncapsulationKey: got %v, want Invalid", err)
	}
	if _, err := NewFromKeys(pub, append(priv, make([]byte, MaxPrivateKeyLen)...), nil); !errors.Is(errors.Invalid, err) {
		t.Errorf("oversized private key: got %v, want Invalid", err)
	}
	if _, err := NewFromKeys(pub, priv, make([]byte, MaxArchiveLen+1)); !errors.Is(errors.Invalid, err) {
		t.Errorf("oversized archive: got %v, want Invalid", err)
	}
	// Under the limit, a malformed record is reported as before (an
	// archive too short for one record is skipped, as it always was).
	if _, err := NewFromKeys(pub, priv, []byte("# EE\ngarbage\n1\n2\n3\n")); err == nil {
		t.Errorf("malformed archive record: expected error")
	}
}
