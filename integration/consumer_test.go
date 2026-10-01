// SPDX-License-Identifier: Apache-2.0

// Package integration uses upspin from outside the upspin module, as a
// module that depends on it would. It reads no files: the keys are generated
// in the test, so it runs wherever the module is a dependency.
package integration

import (
	"bytes"
	"testing"

	"upspin.io/bind"
	"upspin.io/config"
	"upspin.io/factotum"
	"upspin.io/key/inprocess"
	"upspin.io/key/keygen"
	"upspin.io/pack"
	_ "upspin.io/pack/ee"
	"upspin.io/path"
	"upspin.io/upspin"
)

func TestParsePath(t *testing.T) {
	p, err := path.Parse("alice@example.com/dir/file")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.User(), upspin.UserName("alice@example.com"); got != want {
		t.Errorf("User() = %q, want %q", got, want)
	}
	if got, want := p.NElem(), 2; got != want {
		t.Errorf("NElem() = %d, want %d", got, want)
	}
}

// TestEncryptedRoundTrip packs a block with the ee packing, which encrypts
// it for its writer, and unpacks it again.
func TestEncryptedRoundTrip(t *testing.T) {
	const user = upspin.UserName("alice@example.com")
	public, private, _, err := keygen.Generate("p256")
	if err != nil {
		t.Fatal(err)
	}
	f, err := factotum.NewFromKeys([]byte(public), []byte(private), nil)
	if err != nil {
		t.Fatal(err)
	}

	// The ee packer looks up the writer's public key on the key server.
	keys := inprocess.New()
	if err := keys.Put(&upspin.User{Name: user, PublicKey: f.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	if err := bind.RegisterKeyServer(upspin.InProcess, keys); err != nil {
		t.Fatal(err)
	}

	cfg := config.SetUserName(config.New(), user)
	cfg = config.SetFactotum(cfg, f)
	cfg = config.SetKeyEndpoint(cfg, upspin.Endpoint{Transport: upspin.InProcess})

	packer := pack.Lookup(upspin.EEPack)
	if packer == nil {
		t.Fatal("no packer for EEPack")
	}
	name := upspin.PathName(user + "/secret")
	d := &upspin.DirEntry{Name: name, SignedName: name, Writer: user, Packing: upspin.EEPack}
	text := []byte("a block that only alice can read")

	bp, err := packer.Pack(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := bp.Pack(text)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, text) {
		t.Fatal("the packed block holds the cleartext")
	}
	// A real client stores the block and records where; any reference does
	// here, since nothing reads the block back from a store.
	bp.SetLocation(upspin.Location{Reference: "block0"})
	if err := bp.Close(); err != nil {
		t.Fatal(err)
	}

	bu, err := packer.Unpack(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bu.NextBlock(); !ok {
		t.Fatal("no block to unpack")
	}
	clear, err := bu.Unpack(cipher)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clear, text) {
		t.Errorf("unpacked %q, want %q", clear, text)
	}
}
