// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keygen

import (
	"bytes"
	"crypto/mlkem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"upspin.io/factotum"
	"upspin.io/pack/ee"
	"upspin.io/upspin"
)

func init() {
	ee.SetEEPQEnabled(true) // eepq is opt-in; these tests exercise it.
}

var keygenTestCases = []struct {
	secret   string
	proquint string
}{
	{"secretstringforu", "latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj"},
	{"asdaassdwerdsgfd", "kajug-kidod-kajug-latoh.litoj-lanoh-latol-kinoh"},
	{"abracadabramatey", "kajof-lanod-katod-kidod.kanuf-kajot-kajuh-kijun"},
	{"!!!!!!!!!!!!!!!!", "fahod-fahod-fahod-fahod.fahod-fahod-fahod-fahod"},
}

func TestTypeSecretProquintMethod(t *testing.T) {
	for _, c := range keygenTestCases {
		sec := secret(c.secret)
		if sec.proquint() != c.proquint {
			t.Errorf("%+v.proquint() should be %q, got %q", sec, c.proquint, sec.proquint())
		}
	}
}

func TestSecretFromProquint(t *testing.T) {
	for _, c := range keygenTestCases {
		sec := secret(c.secret)
		if !bytes.Equal(secretFromProquint(c.proquint), sec) {
			t.Errorf("secretFromProquint(%q) should be %q, got %q", c.proquint, sec, secretFromProquint(c.proquint))
		}
	}
}

// pqSeed is a 256 bit seed: 16 proquint words in four groups.
const pqSeed = "latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj.kajug-kidod-kajug-latoh.litoj-lanoh-latol-kinoh"

func TestFromSecret(t *testing.T) {
	cases := []struct {
		curve  string
		seed   string
		pubkey string
		valid  bool
	}{
		{"p256", "latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj", "p256\n605083556", true},
		{"p384", "latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj", "p384\n185051353", true},
		{"p521", "latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj", "p521\n608669811", true},
		{"p256+mlkem768", pqSeed, "p256+mlkem768\n515437177", true},
		{"p384+mlkem768", pqSeed, "p384+mlkem768\n316649202", true},
		{"p521+mlkem1024", pqSeed, "p521+mlkem1024\n353933262", true},
		// A post-quantum key type needs a 256 bit seed.
		{"p256+mlkem768", "latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj", "nope", false},
		// A classic key type needs a 128 bit seed.
		{"p256", pqSeed, "nope", false},
		{"p123", "latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj", "nope", false},
		{"p256+mlkem512", pqSeed, "nope", false},
		{"p256+mlkem1024", pqSeed, "nope", false},
	}

	for _, c := range cases {
		pubkey, _, secret, err := FromSecret(c.curve, c.seed)
		if err != nil && c.valid {
			t.Error(err)
			continue
		}
		if err == nil && !c.valid {
			t.Errorf("FromSecret(%q, %q) should raise an error but didn't", c.curve, c.seed)
			continue
		}
		if c.valid && !strings.Contains(pubkey, c.pubkey) {
			if len(pubkey) > 16 {
				pubkey = pubkey[:16]
			}
			t.Errorf("FromSecret(%q, %q) should give %q... as public key, gave %q...", c.curve, c.seed, c.pubkey, pubkey)
			continue
		}
		if c.valid && secret != c.seed {
			t.Errorf("FromSecret(%q, %q) should give %q as secret, gave %q", c.curve, c.seed, c.seed, secret)
		}
	}
}

func TestValidSecretSeed(t *testing.T) {
	cases := []struct {
		proquint string
		valid    bool
	}{
		{"babab-babab-babab-babab.babab-babab-babab-babab", true},
		{"disis-valid-fosoh-matij.disis-valid-fosoh-matij", true},
		{"babab", false},
		{"bbbaa-bbbaa-bbbaa-bbbaa.bbbaa-bbbaa-bbbaa-bbbaa", false},
		{"babab-babab-babab-babab-babab-babab-babab-babab", false},
		{"disis-valid-fosho-matey.disis-valid-fosho-matey", false},
		{"babab-babab-babab-babab.babab-babab-babab-babab/", false},
		{pqSeed, true},
		{"babab-babab-babab-babab.babab-babab-babab-babab.babab-babab-babab-babab.babab-babab-babab-babab", true},
		{"babab-babab-babab-babab-babab-babab-babab-babab.babab-babab-babab-babab.babab-babab-babab-babab", false},
		{"babab-babab-babab-babab.babab-babab-babab-babab.babab-babab-babab-babab", false},
		{"/babab-babab-babab-babab.babab-babab-babab-babab", false},
		{"", false},
		{"83838-83838-83838-83838.83838-83838-83838-83838", false},
	}

	for _, c := range cases {
		if ValidSecretSeed(c.proquint) != c.valid {
			t.Errorf("ValidSecretSeed(%q) returned %t, should be %t", c.proquint, !c.valid, c.valid)
		}
	}
}

// TestFromSecretPostQuantum checks the shape of a post-quantum key pair.
func TestFromSecretPostQuantum(t *testing.T) {
	const seed = pqSeed
	pub, priv, _, err := FromSecret("p256+mlkem768", seed)
	if err != nil {
		t.Fatal(err)
	}
	pubLines := strings.Split(pub, "\n")
	if len(pubLines) != 5 || pubLines[4] != "" {
		t.Fatalf("public key has %d lines, want 4 plus a terminator: %q", len(pubLines)-1, pub)
	}
	privLines := strings.Split(priv, "\n")
	if len(privLines) != 3 || privLines[2] != "" {
		t.Fatalf("private key has %d lines, want 2 plus a terminator: %q", len(privLines)-1, priv)
	}

	// The ML-KEM part parses, and the pair loads into a factotum.
	ek, err := factotum.ParseEncapsulationKey(upspin.PublicKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(ek.Bytes()); got != mlkem.EncapsulationKeySize768 {
		t.Errorf("encapsulation key has %d bytes, want %d", got, mlkem.EncapsulationKeySize768)
	}
	f, err := factotum.NewFromKeys([]byte(pub), []byte(priv), nil)
	if err != nil {
		t.Fatalf("NewFromKeys: %v", err)
	}
	if f.PublicKey() != upspin.PublicKey(pub) {
		t.Errorf("factotum public key does not match generated key")
	}

	// Generation is deterministic, so the seed alone is a full backup.
	pub2, priv2, _, err := FromSecret("p256+mlkem768", seed)
	if err != nil {
		t.Fatal(err)
	}
	if pub2 != pub || priv2 != priv {
		t.Errorf("FromSecret is not deterministic for post-quantum keys")
	}

	// ML-KEM-1024 keys are larger.
	pub, _, _, err = FromSecret("p521+mlkem1024", seed)
	if err != nil {
		t.Fatal(err)
	}
	ek, err = factotum.ParseEncapsulationKey(upspin.PublicKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(ek.Bytes()); got != mlkem.EncapsulationKeySize1024 {
		t.Errorf("encapsulation key has %d bytes, want %d", got, mlkem.EncapsulationKeySize1024)
	}
}

// TestGeneratePostQuantum checks that Generate accepts a post-quantum key
// type and yields a seed that reproduces the pair.
func TestGeneratePostQuantum(t *testing.T) {
	pub, priv, seed, err := Generate("p521+mlkem1024")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidSecretSeed(seed) || len(seed) != 95 {
		t.Fatalf("Generate returned invalid seed %q", seed)
	}
	pub2, priv2, _, err := FromSecret("p521+mlkem1024", seed)
	if err != nil {
		t.Fatal(err)
	}
	if pub2 != pub || priv2 != priv {
		t.Errorf("FromSecret(seed) does not reproduce Generate's key pair")
	}
}

// FuzzSecretFromProquint feeds the seed parser what a user could type on
// the command line. It must not panic, and a seed that ValidSecretSeed
// accepts must round-trip through secretFromProquint and proquint.
func FuzzSecretFromProquint(f *testing.F) {
	f.Add("latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj")
	f.Add(pqSeed)
	f.Add("babab")
	f.Add("")
	f.Add("babab-babab-babab-babab.babab-babab-babab-babab/")
	f.Fuzz(func(t *testing.T, seed string) {
		ok := ValidSecretSeed(seed)
		b := secretFromProquint(seed)
		if ok && b.proquint() != seed {
			t.Errorf("valid seed %q does not round-trip", seed)
		}
	})
}

// TestSaveKeys covers the file side of keygen: a first save, the refusal
// to overwrite without rotate, the refusal to rotate without prior keys,
// a rotation that archives the old pair to secret2.upspinkey in the form
// factotum reads back, a duplicate save that changes nothing, and the
// secret seed written as a comment after the private key.
func TestSaveKeys(t *testing.T) {
	const (
		seed1 = "latoj-katuf-kijuh-latuh.lanon-kunol-kinoz-lanuj"
		seed2 = "kajug-kidod-kajug-latoh.litoj-lanoh-latol-kinoh"
	)
	dir := t.TempDir()
	pub1, priv1, _, err := FromSecret("p256", seed1)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, _, err := FromSecret("p384", seed2)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return string(b)
	}

	// Rotating before any keys exist is an error.
	if err := SaveKeys(dir, true, pub1, priv1, seed1); err == nil {
		t.Error("rotate with no prior keys: expected error")
	}
	// A first save writes both files; the seed follows the private key.
	if err := SaveKeys(dir, false, pub1, priv1, seed1); err != nil {
		t.Fatal(err)
	}
	if got := read("public.upspinkey"); got != pub1 {
		t.Errorf("public.upspinkey = %q, want %q", got, pub1)
	}
	if got, want := read("secret.upspinkey"), strings.TrimSpace(priv1)+" # "+seed1+"\n"; got != want {
		t.Errorf("secret.upspinkey = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "secret2.upspinkey")); !os.IsNotExist(err) {
		t.Errorf("secret2.upspinkey exists after a first save")
	}
	// Saving again without rotate is refused.
	if err := SaveKeys(dir, false, pub2, priv2, seed2); err == nil {
		t.Error("save over existing keys without rotate: expected error")
	}
	if got := read("public.upspinkey"); got != pub1 {
		t.Errorf("refused save changed public.upspinkey")
	}
	// Rotation archives the old pair and installs the new one.
	if err := SaveKeys(dir, true, pub2, priv2, seed2); err != nil {
		t.Fatal(err)
	}
	if got := read("public.upspinkey"); got != pub2 {
		t.Errorf("after rotate public.upspinkey = %q, want %q", got, pub2)
	}
	archive := read("secret2.upspinkey")
	if !strings.HasPrefix(archive, "# EE") || !strings.Contains(archive, pub1) || !strings.Contains(archive, strings.TrimSpace(priv1)) {
		t.Errorf("secret2.upspinkey does not hold the old pair: %q", archive)
	}
	// factotum reads the archive back and knows both keys.
	f, err := factotum.NewFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f.PublicKey() != upspin.PublicKey(pub2) {
		t.Errorf("factotum current key is not the rotated key")
	}
	if _, err := f.PublicKeyFromHash(factotum.KeyHash(upspin.PublicKey(pub1))); err != nil {
		t.Errorf("factotum does not know the archived key: %v", err)
	}
	// A rotation to the same pair changes nothing.
	before := archive
	if err := SaveKeys(dir, true, pub2, read("secret.upspinkey"), ""); err != nil {
		t.Fatal(err)
	}
	if read("secret2.upspinkey") != before {
		t.Errorf("rotating to the same keys grew the archive")
	}
	// A save into a directory that does not exist yet creates it.
	sub := filepath.Join(dir, "new", "deeper")
	if err := SaveKeys(sub, false, pub1, priv1, ""); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(func() string { b, _ := os.ReadFile(filepath.Join(sub, "secret.upspinkey")); return string(b) }()), strings.TrimSpace(priv1); got != want {
		t.Errorf("secret.upspinkey without a seed = %q, want %q", got, want)
	}
}
