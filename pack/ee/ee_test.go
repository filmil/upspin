// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ee_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"upspin.io/bind"
	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/pack"
	"upspin.io/pack/ee"
	"upspin.io/pack/internal/packtest"
	"upspin.io/test/testfixtures"
	"upspin.io/test/testutil"
	"upspin.io/upspin"
)

const (
	packing = upspin.EEPack
)

func init() {
	// The eepq packing is off by default; see TestEEPQDisabledByDefault.
	ee.SetEEPQEnabled(true)
}

func TestRegister(t *testing.T) {
	p := pack.Lookup(upspin.EEPack)
	if p == nil {
		t.Fatal("Lookup failed")
	}
	if p.Packing() != upspin.EEPack {
		t.Fatalf("expected EEPack, got %q", p)
	}
}

// packBlob packs text according to the parameters and returns the cipher.
func packBlob(t *testing.T, cfg upspin.Config, packer upspin.Packer, d *upspin.DirEntry, text []byte) []byte {
	d.Packing = packer.Packing()
	bp, err := packer.Pack(cfg, d)
	if err != nil {
		t.Fatal("packBlob:", err)
	}
	cipher, err := bp.Pack(text)
	if err != nil {
		t.Fatal("packBlob:", err)
	}
	bp.SetLocation(upspin.Location{Reference: "dummy"})
	if err := bp.Close(); err != nil {
		t.Fatal("packBlob:", err)
	}
	return cipher
}

// unpackBlob unpacks cipher according to the parameters and returns the plain text.
func unpackBlob(t *testing.T, cfg upspin.Config, packer upspin.Packer, d *upspin.DirEntry, cipher []byte) []byte {
	bp, err := packer.Unpack(cfg, d)
	if err != nil {
		t.Fatal("unpackBlob:", err)
	}
	if _, ok := bp.NextBlock(); !ok {
		t.Fatal("unpackBlob: no next block")
	}
	text, err := bp.Unpack(cipher)
	if err != nil {
		t.Fatal("unpackBlob:", err)
	}
	return text
}

func testPackAndUnpack(t *testing.T, cfg upspin.Config, packer upspin.Packer, name upspin.PathName, text []byte) {
	// First pack.
	d := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Writer:     cfg.UserName(),
	}
	cipher := packBlob(t, cfg, packer, d, text)

	// Now unpack.
	clear := unpackBlob(t, cfg, packer, d, cipher)

	if !bytes.Equal(text, clear) {
		t.Errorf("text: expected %q; got %q", text, clear)
	}
	if d.SignedName != d.Name {
		t.Errorf("SignedName: expected %q; got %q", d.Name, d.SignedName)
	}
}

func testPackNameAndUnpack(t *testing.T, cfg upspin.Config, packer upspin.Packer, name, newName upspin.PathName, text []byte) {
	// First pack.
	d := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Writer:     cfg.UserName(),
	}
	cipher := packBlob(t, cfg, packer, d, text)

	// Name to newName.
	if err := packer.Name(cfg, d, newName); err != nil {
		t.Errorf("Name failed: %s", err)
	}
	if d.Name != newName {
		t.Errorf("Name failed to set the name")
	}

	// Now unpack.
	clear := unpackBlob(t, cfg, packer, d, cipher)

	if !bytes.Equal(text, clear) {
		t.Errorf("text: expected %q; got %q", text, clear)
	}
}

func TestPack256(t *testing.T) {
	const (
		user upspin.UserName = "joe@upspin.io"
		name                 = upspin.PathName(user + "/file/of/user.256")
		text                 = "this is some text 256"
	)
	cfg, packer := setup(user)
	testPackAndUnpack(t, cfg, packer, name, []byte(text))
}

func TestName256(t *testing.T) {
	const (
		user    upspin.UserName = "joe@upspin.io"
		name                    = upspin.PathName(user + "/file/of/user.256")
		newName                 = upspin.PathName(user + "/file/of/user.256.2")
		text                    = "this is some text 256"
	)
	cfg, packer := setup(user)
	testPackNameAndUnpack(t, cfg, packer, name, newName, []byte(text))
}

func benchmarkPack(b *testing.B, curveName string, fileSize int, unpack bool) {
	b.SetBytes(int64(fileSize))
	const user upspin.UserName = "joe@upspin.io"
	data := make([]byte, fileSize)
	n, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	if n != fileSize {
		b.Fatalf("Not enough random bytes read: %d", n)
	}
	data = data[:n]
	name := upspin.PathName(fmt.Sprintf("%s/file/of/user.%d", user, packing))
	cfg, packer := setup(user)
	for i := 0; i < b.N; i++ {
		d := &upspin.DirEntry{
			Name:       name,
			SignedName: name,
			Writer:     cfg.UserName(),
			Packing:    packer.Packing(),
		}
		bp, err := packer.Pack(cfg, d)
		if err != nil {
			b.Fatal(err)
		}
		cipher, err := bp.Pack(data)
		if err != nil {
			b.Fatal(err)
		}
		bp.SetLocation(upspin.Location{Reference: "dummy"})
		if err := bp.Close(); err != nil {
			b.Fatal(err)
		}
		if !unpack {
			continue
		}
		bu, err := packer.Unpack(cfg, d)
		if err != nil {
			b.Fatal(err)
		}
		if _, ok := bu.NextBlock(); !ok {
			b.Fatal("no next block")
		}
		clear, err := bu.Unpack(cipher)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(clear, data) {
			b.Fatal("cleartext mismatch")
		}
	}
}

const unpack = true

func BenchmarkPack256_1byte(b *testing.B)  { benchmarkPack(b, "p256", 1, !unpack) }
func BenchmarkPack256_1kbyte(b *testing.B) { benchmarkPack(b, "p256", 1024, !unpack) }
func BenchmarkPack256_1Mbyte(b *testing.B) { benchmarkPack(b, "p256", 1024*1024, !unpack) }

func BenchmarkPackUnpack256_1byte(b *testing.B)  { benchmarkPack(b, "p256", 1, unpack) }
func BenchmarkPackUnpack256_1kbyte(b *testing.B) { benchmarkPack(b, "p256", 1024, unpack) }
func BenchmarkPackUnpack256_1Mbyte(b *testing.B) {
	benchmarkPack(b, "p256", 1024*1024, unpack)
}

// shareBlob updates the packdata of a blob such that the public keys given are readers of the blob.
func shareBlob(t *testing.T, cfg upspin.Config, packer upspin.Packer, readers []upspin.PublicKey, packdata *[]byte) {
	pd := make([]*[]byte, 1)
	pd[0] = packdata
	packer.Share(cfg, readers, pd)
}

func TestSharing(t *testing.T) {
	// TODO This could be cleaned up to be more like TestCountersign.
	// joe@google.com is the owner of a file that is shared with bob@foo.com.
	const (
		joesUserName   upspin.UserName = "joe@upspin.io"
		pathName                       = upspin.PathName(joesUserName + "/secret_file_shared_with_bob")
		bobsUserName   upspin.UserName = "bob@upspin.io"
		carlasUserName upspin.UserName = "carla@baz.edu"
		text                           = "bob, here's the secret file. Sincerely, The Joe."
	)
	joePublic := upspin.PublicKey("p256\n104278369061367353805983276707664349405797936579880352274235000127123465616334\n26941412685198548642075210264642864401950753555952207894712845271039438170192\n")
	bobPublic := upspin.PublicKey("p256\n22501350716439586308300487995594907386227865907589820632958610970814693581908\n104071495646780593180743128812641149143422089655848205222288250096821814372528\n")
	carlaPublic := upspin.PublicKey("p384\n26172614276096813357206176213406982397222536659671409755310805362042028026922579207014531049688734331134000100158544\n17028658482487767962568267600820350664652897469525797908053707470805274016916949610485516295521856564391853226932191\n")

	// Set up Joe as the creator/owner.
	joecfg, packer := setup(joesUserName)

	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
	}
	d.Writer = joecfg.UserName()
	cipher := packBlob(t, joecfg, packer, d, []byte(text))
	// Share with Bob and Carla.
	shareBlob(t, joecfg, packer, []upspin.PublicKey{joePublic, bobPublic, carlaPublic}, &d.Packdata)

	readers, err := packer.ReaderHashes(d.Packdata)
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 3 {
		t.Errorf("Expected 3 readerhashes, got %d", len(readers))
	}
	hash0 := factotum.KeyHash(joePublic)
	hash1 := factotum.KeyHash(bobPublic)
	hash2 := factotum.KeyHash(carlaPublic)
	if !bytes.Equal(readers[0], hash0) || !bytes.Equal(readers[1], hash1) || !bytes.Equal(readers[2], hash2) {
		t.Errorf("text: expected %q; got %q", [][]byte{hash0, hash1, hash2}, readers)
	}

	// Now load Bob as the current user.
	bobcfg, packer := setup(bobsUserName)
	bobcfg = config.SetKeyEndpoint(bobcfg, upspin.Endpoint{Transport: upspin.InProcess})
	clear := unpackBlob(t, bobcfg, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("Expected %s, got %s", text, clear)
	}

	// Load Carla as the current user.
	carlacfg, packer := setup(carlasUserName)
	carlacfg = config.SetKeyEndpoint(carlacfg, upspin.Endpoint{Transport: upspin.InProcess})
	clear = unpackBlob(t, carlacfg, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("Expected %s, got %s", text, clear)
	}
}

func TestBadSharing(t *testing.T) {
	// joe@google.com is the owner of a file that is attempting to be shared with bob@foo.com, but share wasn't called.
	const (
		joesUserName upspin.UserName = "joe@upspin.io"
		pathName                     = upspin.PathName(joesUserName + "/secret_file_shared_with_bob")
		bobsUserName upspin.UserName = "bob@upspin.io"
		text                         = "bob, here's the secret file. sincerely, joe."
	)
	cfg, packer := setup(joesUserName)

	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
	}
	d.Writer = cfg.UserName()
	packBlob(t, cfg, packer, d, []byte(text))

	// Don't share with Bob (do nothing).

	// Now load Bob as the current user.
	cfg = config.SetUserName(cfg, bobsUserName)
	f, err := factotum.NewFromDir(testutil.Repo("key", "testdata", "bob"))
	if err != nil {
		t.Fatal(err)
	}
	cfg = config.SetFactotum(cfg, f)

	// Bob can't unpack.
	_, err = packer.Unpack(cfg, d)
	if err == nil {
		t.Fatal("Expected error, got none.")
	}
	if !errors.Is(errors.CannotDecrypt, err) {
		t.Fatalf("Expected CannotDecrypt error, got %s", err)
	}
}

func TestCountersign(t *testing.T) {
	const (
		joeUserName upspin.UserName = "joe@upspin.io"
		bobUserName upspin.UserName = "bob@upspin.io"
		pathName                    = upspin.PathName(joeUserName + "/secret_for_bob")
		text                        = "bob, here's the secret file. Sincerely, The Joe."
	)
	joeConfig, _ := setup(joeUserName)
	joePublic := joeConfig.Factotum().PublicKey()
	bobConfig, packer := setup(bobUserName)
	bobPublic := bobConfig.Factotum().PublicKey()
	bobConfig = config.SetKeyEndpoint(bobConfig, upspin.Endpoint{Transport: upspin.InProcess})

	// Share file with Bob.
	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
	}
	d.Writer = joeConfig.UserName()
	cipher := packBlob(t, joeConfig, packer, d, []byte(text))
	shareBlob(t, joeConfig, packer, []upspin.PublicKey{joePublic, bobPublic}, &d.Packdata)

	// Emulate Joe executing "upspin keygen -rotate".
	f2, err := factotum.NewFromDir(testutil.Repo("key", "testdata", "joe2"))
	if err != nil {
		t.Fatalf("cannot create second (key-rotated) factotum for joe: %v", err)
	}
	joeConfig = config.SetFactotum(joeConfig, f2)

	// We know from TestSharing that Bob can read. Try again with Countersign.
	err = packer.Countersign(joePublic, joeConfig.Factotum(), d)
	if err != nil {
		t.Fatal(err)
	}
	clear := unpackBlob(t, bobConfig, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("Expected %q, got %q", text, clear)
	}

	// And yet again, after emulating Joe executing "upspin rotate".
	clear = unpackBlob(t, bobConfig, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("Expected %q, got %q", text, clear)
	}
}

func cfgFor(name upspin.UserName) (upspin.Config, upspin.Packer) {
	return cfgForPacking(name, packing)
}

// cfgForPacking returns a config for the named test user, whose keys are in
// key/testdata under the local part of the name, and the packer for p.
func cfgForPacking(name upspin.UserName, p upspin.Packing) (upspin.Config, upspin.Packer) {
	cfg := config.SetUserName(config.New(), name)
	packer := pack.Lookup(p)
	j := strings.IndexByte(string(name), '@')
	if j < 0 {
		log.Fatalf("malformed username %s", name)
	}
	f, err := factotum.NewFromDir(testutil.Repo("key", "testdata", string(name[:j])))
	if err != nil {
		log.Fatalf("unable to initialize factotum for %s", string(name[:j]))
	}
	cfg = config.SetFactotum(cfg, f)
	cfg = config.SetKeyEndpoint(cfg, upspin.Endpoint{Transport: upspin.InProcess})
	return cfg, packer
}

func setup(name upspin.UserName) (upspin.Config, upspin.Packer) {
	return setupPacking(name, packing)
}

// setupPacking is setup with a choice of packing. The in-process key server
// knows joe and bob, who have classic keys, and pqjoe and pqbob, whose keys
// have an ML-KEM component.
func setupPacking(name upspin.UserName, p upspin.Packing) (upspin.Config, upspin.Packer) {
	cfg, packer := cfgForPacking(name, p)

	mockKey := &dummyKey{}
	for _, u := range []upspin.UserName{"joe@upspin.io", "bob@upspin.io", "pqjoe@upspin.io", "pqbob@upspin.io"} {
		c, _ := cfgFor(u)
		mockKey.userToMatch = append(mockKey.userToMatch, c.UserName())
		mockKey.keyToReturn = append(mockKey.keyToReturn, c.Factotum().PublicKey())
	}
	bind.RegisterKeyServer(upspin.InProcess, mockKey)
	return cfg, packer
}

// dummyKey is a User service that returns a key for a given user.
type dummyKey struct {
	testfixtures.DummyKey
	// The two slices go together
	userToMatch  []upspin.UserName
	keyToReturn  []upspin.PublicKey
	returnedKeys int
}

var _ upspin.KeyServer = (*dummyKey)(nil)

func (d *dummyKey) Lookup(userName upspin.UserName) (*upspin.User, error) {
	const op errors.Op = "pack/ee.dummyKey.Lookup"
	for i, u := range d.userToMatch {
		if u == userName {
			d.returnedKeys++
			user := &upspin.User{
				Name:      userName,
				PublicKey: d.keyToReturn[i],
			}
			return user, nil
		}
	}
	return nil, errors.E(op, userName, errors.NotExist, "user not found")
}
func (d *dummyKey) Dial(cc upspin.Config, e upspin.Endpoint) (upspin.Service, error) {
	return d, nil
}

func TestMultiBlockRoundTrip(t *testing.T) {
	const userName = upspin.UserName("aly@upspin.io")
	cfg, packer := setup(userName)
	packtest.TestMultiBlockRoundTrip(t, cfg, packer, userName)
}

func TestConsistentKeyStream(t *testing.T) {
	// This test that the EE packer with different block sizes still
	// generates the same ciphertext when all blocks are concatenated.
	blockSizes := []int{777, 1024, 4001, 92341, 1024 * 1024}
	const (
		user upspin.UserName = "joe@upspin.io"
		name                 = upspin.PathName(user + "/file/of/user")
	)

	cfg, packer := setup(user)
	de := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Writer:     cfg.UserName(),
		Packing:    packer.Packing(),
	}

	// Generate a little over 2MB of random data.
	data := make([]byte, 2*1024*1024+3)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	// Create a new key to re-use for each separate pack operation.
	dkey, blockCipher, err := ee.NewKeyAndCipher()
	if err != nil {
		t.Fatal(err)
	}

	// Generate the expected ciphertext in one operation.
	// We will then compare the ciphertext generated over multiple blocks
	// against this canonical reference.
	wantCipherText := make([]byte, len(data))
	iv := make([]byte, blockCipher.BlockSize()) // zero
	cipher.NewCTR(blockCipher, iv).XORKeyStream(wantCipherText, data)

	// Encrypt data at various block sizes.
	dirEntries := map[int]upspin.DirEntry{}
	for _, bs := range blockSizes {
		t.Logf("encrypt blockSize=%d", bs)

		bp, err := packer.Pack(cfg, de)
		if err != nil {
			t.Fatal(err)
		}

		// Replace the random dkey/cipher with our own.
		// Pass a copy of dkey, as the original will get zeroed on close.
		ee.SetblockPacker(bp, append([]byte(nil), dkey...), blockCipher)

		var gotCipherText []byte
		for i := 0; i < len(data); i += bs {
			clear := data[i:]
			if len(clear) > bs {
				clear = clear[:bs]
			}
			cipher, err := bp.Pack(clear)
			if err != nil {
				t.Fatal(err)
			}
			gotCipherText = append(gotCipherText, cipher...)
			bp.SetLocation(upspin.Location{Reference: "dummy"})
		}
		if err := bp.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotCipherText, wantCipherText) {
			t.Fatalf("cipherText for block size %d did not match", bs)
		}

		dirEntries[bs] = *de
		de.Packdata = nil
		de.Blocks = nil
	}

	// Decrypt data and verify.
	for _, bs := range blockSizes {
		t.Logf("decrypt blockSize=%d", bs)

		de := dirEntries[bs]
		bu, err := packer.Unpack(cfg, &de)
		if err != nil {
			t.Fatal(err)
		}

		got := make([]byte, len(data))

		for i := 0; i < len(data); i += bs {
			if _, ok := bu.NextBlock(); !ok {
				t.Fatal("expected next block, didn't find one")
			}
			cipher := wantCipherText[i:]
			if len(cipher) > bs {
				cipher = cipher[:bs]
			}
			clear, err := bu.Unpack(cipher)
			if err != nil {
				t.Fatal(err)
			}
			copy(got[i:], clear)
		}

		if !bytes.Equal(data, got) {
			t.Errorf("cleartext for blockSize=%d does not match input", bs)
		}
	}
}

func TestAllReaders(t *testing.T) {
	const (
		userName  = upspin.UserName("joe@upspin.io")
		otherName = upspin.UserName("aly@upspin.io")
		pathName  = upspin.PathName(userName + "/dir/file")
		content   = "Some text"
	)

	cfg, packer := setup(userName)
	cfg2, _ := setup(otherName)

	cfg = config.SetKeyEndpoint(cfg, upspin.Endpoint{Transport: upspin.InProcess})
	cfg2 = config.SetKeyEndpoint(cfg2, upspin.Endpoint{Transport: upspin.InProcess})

	de := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
		Writer:     userName,
		Packing:    packer.Packing(),
	}

	cipher := packBlob(t, cfg, packer, de, []byte(content))

	ok, err := packer.UnpackableByAll(de)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("UnpackableByAll returned true, want false")
	}

	if _, err := packer.Unpack(cfg2, de); err == nil {
		t.Fatalf("expected error unpacking as %s, got nil", otherName)
	}

	readers := []upspin.PublicKey{
		cfg.Factotum().PublicKey(),
		upspin.AllUsersKey,
	}
	packer.Share(cfg, readers, []*[]byte{&de.Packdata})

	ok, err = packer.UnpackableByAll(de)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("UnpackableByAll returned false, want true")
	}

	bp, err := packer.Unpack(cfg2, de)
	if err != nil {
		t.Fatalf("error unpacking as %s: %v", otherName, err)
	}
	if _, ok := bp.NextBlock(); !ok {
		t.Fatalf("error unpacking as %s: %v", otherName, err)
	}
	clear, err := bp.Unpack(cipher)
	if err != nil {
		t.Fatalf("error unpacking as %s: %v", otherName, err)
	}

	if got, want := string(clear), content; got != want {
		t.Errorf("content unpacked as %q, want %q", got, want)
	}
}

// The tests below exercise EEPQPack, whose key wrapping combines ECDH with
// ML-KEM. Users pqjoe (p256+mlkem768) and pqbob (p521+mlkem1024) have
// post-quantum keys; joe and bob have classic keys.

const (
	pqJoe upspin.UserName = "pqjoe@upspin.io"
	pqBob upspin.UserName = "pqbob@upspin.io"
)

func TestRegisterPQ(t *testing.T) {
	p := pack.Lookup(upspin.EEPQPack)
	if p == nil {
		t.Fatal("Lookup failed")
	}
	if p.Packing() != upspin.EEPQPack {
		t.Fatalf("expected EEPQPack, got %q", p)
	}
	if p.String() != "eepq" {
		t.Errorf("expected packer name eepq, got %q", p)
	}
	if pack.LookupByName("eepq") != p {
		t.Error("LookupByName(eepq) did not find the packer")
	}
}

func TestPackPQ(t *testing.T) {
	const (
		name = upspin.PathName(pqJoe + "/file/of/user.pq")
		text = "this is some text for the quantum age"
	)
	cfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	testPackAndUnpack(t, cfg, packer, name, []byte(text))

	// ML-KEM-1024 with P-521.
	cfg, packer = setupPacking(pqBob, upspin.EEPQPack)
	testPackAndUnpack(t, cfg, packer, upspin.PathName(pqBob+"/file"), []byte(text))
}

func TestNamePQ(t *testing.T) {
	const (
		name    = upspin.PathName(pqJoe + "/file/of/user.pq")
		newName = upspin.PathName(pqJoe + "/file/of/user.pq.2")
		text    = "this is some text for the quantum age"
	)
	cfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	testPackNameAndUnpack(t, cfg, packer, name, newName, []byte(text))
}

// TestPackClassicWithPQKey checks that a user with a post-quantum key can
// still write and read the classic EEPack, which uses only the ECDSA part.
func TestPackClassicWithPQKey(t *testing.T) {
	const (
		name = upspin.PathName(pqJoe + "/file/of/user.classic")
		text = "classic packing, post-quantum key"
	)
	cfg, packer := setupPacking(pqJoe, upspin.EEPack)
	testPackAndUnpack(t, cfg, packer, name, []byte(text))
}

// TestPQRequiresPQKey checks that EEPQPack refuses to wrap for a classic key.
func TestPQRequiresPQKey(t *testing.T) {
	const (
		user upspin.UserName = "joe@upspin.io"
		name                 = upspin.PathName(user + "/file")
	)
	cfg, packer := setupPacking(user, upspin.EEPQPack)
	d := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Writer:     user,
		Packing:    packer.Packing(),
	}
	bp, err := packer.Pack(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bp.Pack([]byte("text")); err != nil {
		t.Fatal(err)
	}
	bp.SetLocation(upspin.Location{Reference: "dummy"})
	err = bp.Close()
	if err == nil {
		t.Fatal("Close with a classic key under EEPQPack: expected error")
	}
	if !errors.Is(errors.NotExist, err) {
		t.Errorf("Close with a classic key under EEPQPack: got %v, want NotExist", err)
	}
}

func TestSharingPQ(t *testing.T) {
	const (
		pathName = upspin.PathName(pqJoe + "/secret_file_shared_with_pqbob")
		text     = "pqbob, here's the secret file. Sincerely, pqjoe."
	)
	joecfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	joePublic := joecfg.Factotum().PublicKey()
	bobcfg, _ := setupPacking(pqBob, upspin.EEPQPack)
	bobPublic := bobcfg.Factotum().PublicKey()
	classicCfg, _ := setupPacking("bob@upspin.io", upspin.EEPQPack)
	classicPublic := classicCfg.Factotum().PublicKey()

	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
		Writer:     pqJoe,
	}
	cipher := packBlob(t, joecfg, packer, d, []byte(text))

	// Share with pqbob and with bob, whose classic key cannot be wrapped for.
	shareBlob(t, joecfg, packer, []upspin.PublicKey{joePublic, bobPublic, classicPublic}, &d.Packdata)

	readers, err := packer.ReaderHashes(d.Packdata)
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 2 {
		t.Fatalf("expected 2 reader hashes, got %d", len(readers))
	}
	if !bytes.Equal(readers[0], factotum.KeyHash(joePublic)) || !bytes.Equal(readers[1], factotum.KeyHash(bobPublic)) {
		t.Errorf("reader hashes do not match pqjoe and pqbob")
	}

	// pqbob can read.
	clear := unpackBlob(t, bobcfg, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("expected %q, got %q", text, clear)
	}

	// bob cannot.
	if _, err := packer.Unpack(classicCfg, d); !errors.Is(errors.CannotDecrypt, err) {
		t.Errorf("classic bob unpacking EEPQPack: got %v, want CannotDecrypt", err)
	}
}

// TestTamperedEncapsulationPQ checks that a modified ML-KEM ciphertext
// makes unwrapping fail rather than yield a wrong key.
func TestTamperedEncapsulationPQ(t *testing.T) {
	const (
		pathName = upspin.PathName(pqJoe + "/tampered")
		text     = "some text"
	)
	cfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
		Writer:     pqJoe,
	}
	packBlob(t, cfg, packer, d, []byte(text))
	if err := ee.FlipEncapBit(&d.Packdata); err != nil {
		t.Fatal(err)
	}
	if _, err := packer.Unpack(cfg, d); err == nil {
		t.Fatal("Unpack with tampered ML-KEM ciphertext: expected error")
	}
}

func TestCountersignPQ(t *testing.T) {
	const (
		pathName = upspin.PathName(pqJoe + "/secret_for_pqbob")
		text     = "pqbob, here's the secret file. Sincerely, pqjoe."
	)
	joeConfig, _ := setupPacking(pqJoe, upspin.EEPQPack)
	joePublic := joeConfig.Factotum().PublicKey()
	bobConfig, packer := setupPacking(pqBob, upspin.EEPQPack)
	bobPublic := bobConfig.Factotum().PublicKey()

	d := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
		Writer:     pqJoe,
	}
	cipher := packBlob(t, joeConfig, packer, d, []byte(text))
	shareBlob(t, joeConfig, packer, []upspin.PublicKey{joePublic, bobPublic}, &d.Packdata)

	// Emulate pqjoe executing "upspin keygen -rotate -curve p256+mlkem1024".
	// The archived key must still unwrap so the entry can be countersigned.
	f2, err := factotum.NewFromDir(testutil.Repo("key", "testdata", "pqjoe2"))
	if err != nil {
		t.Fatalf("cannot create second (key-rotated) factotum for pqjoe: %v", err)
	}
	if err := packer.Countersign(joePublic, f2, d); err != nil {
		t.Fatal(err)
	}
	clear := unpackBlob(t, bobConfig, packer, d, cipher)
	if string(clear) != text {
		t.Errorf("expected %q, got %q", text, clear)
	}
}

func TestMultiBlockRoundTripPQ(t *testing.T) {
	cfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	packtest.TestMultiBlockRoundTrip(t, cfg, packer, pqJoe)
}

func TestAllReadersPQ(t *testing.T) {
	const (
		pathName = upspin.PathName(pqJoe + "/dir/file")
		content  = "Some text"
	)
	cfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	cfg2, _ := setupPacking(pqBob, upspin.EEPQPack)

	de := &upspin.DirEntry{
		Name:       pathName,
		SignedName: pathName,
		Writer:     pqJoe,
		Packing:    packer.Packing(),
	}
	cipher := packBlob(t, cfg, packer, de, []byte(content))

	ok, err := packer.UnpackableByAll(de)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("UnpackableByAll returned true, want false")
	}
	if _, err := packer.Unpack(cfg2, de); err == nil {
		t.Fatalf("expected error unpacking as %s, got nil", pqBob)
	}

	readers := []upspin.PublicKey{cfg.Factotum().PublicKey(), upspin.AllUsersKey}
	packer.Share(cfg, readers, []*[]byte{&de.Packdata})

	ok, err = packer.UnpackableByAll(de)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("UnpackableByAll returned false, want true")
	}
	clear := unpackBlob(t, cfg2, packer, de, cipher)
	if got, want := string(clear), content; got != want {
		t.Errorf("content unpacked as %q, want %q", got, want)
	}
}

// golden is the JSON form of a packed entry kept under testdata, so that a
// later change to the code is checked against bytes an earlier binary wrote.
type golden struct {
	Name, Writer, Text, Ciphertext, Packdata, BlockPackdata string
	Time, BlockSize                                         int64
}

// TestGoldenGen prints, as JSON between GOLDEN-BEGIN and GOLDEN-END lines,
// a fresh eepq entry for pqjoe when UPSPIN_GOLDEN_GEN is set, so that the
// fixture read by TestUnpackGoldenEEPQ can be regenerated on purpose.
func TestGoldenGen(t *testing.T) {
	if os.Getenv("UPSPIN_GOLDEN_GEN") == "" {
		t.Skip("set UPSPIN_GOLDEN_GEN to print a new golden entry")
	}
	const text = "golden eepq packdata written by the code that introduced EEPQPack"
	name := upspin.PathName(pqJoe + "/golden/file.txt")
	cfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	d := &upspin.DirEntry{Name: name, SignedName: name, Writer: pqJoe, Time: 1725700000}
	cipher := packBlob(t, cfg, packer, d, []byte(text))
	out, err := json.MarshalIndent(golden{
		Name: string(name), Writer: string(pqJoe), Text: text, Time: int64(d.Time),
		Ciphertext: hex.EncodeToString(cipher), Packdata: hex.EncodeToString(d.Packdata),
		BlockPackdata: hex.EncodeToString(d.Blocks[0].Packdata), BlockSize: d.Blocks[0].Size,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("GOLDEN-BEGIN\n%s\nGOLDEN-END\n", out)
}

// TestUnpackGoldenEE unpacks an EEPack entry written by the code at the fork
// point, before EEPQPack existed (testdata/ee-golden.json), so that stored
// data is checked against the old binary's output rather than against this
// package's own understanding of its format.
func TestUnpackGoldenEE(t *testing.T) {
	testUnpackGolden(t, "ee-golden.json", upspin.EEPack)
}

// TestUnpackGoldenEEPQ unpacks the EEPQPack entry in testdata/eepq-golden.json,
// written by the code that introduced the packing. A change to the eepq
// wire format or key derivation fails here and must update the fixture on
// purpose.
func TestUnpackGoldenEEPQ(t *testing.T) {
	testUnpackGolden(t, "eepq-golden.json", upspin.EEPQPack)
}

func testUnpackGolden(t *testing.T, file string, packing upspin.Packing) {
	var g golden
	b, err := os.ReadFile(testutil.Repo("pack", "ee", "testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cfg, packer := setupPacking(upspin.UserName(g.Writer), packing)
	d := &upspin.DirEntry{
		Name:       upspin.PathName(g.Name),
		SignedName: upspin.PathName(g.Name),
		Writer:     upspin.UserName(g.Writer),
		Packing:    packing,
		Time:       upspin.Time(g.Time),
		Packdata:   unhex(g.Packdata),
		Blocks: []upspin.DirBlock{{
			Location: upspin.Location{Reference: "golden"},
			Size:     g.BlockSize,
			Packdata: unhex(g.BlockPackdata),
		}},
	}
	clear := unpackBlob(t, cfg, packer, d, unhex(g.Ciphertext))
	if string(clear) != g.Text {
		t.Errorf("golden text: got %q, want %q", clear, g.Text)
	}
}

// TestFreshWrap checks the property the wrapping depends on: every wrap
// draws a fresh ephemeral ECDH key and, under EEPQPack, a fresh ML-KEM
// encapsulation, so that two wraps of the same key for the same reader,
// and the wraps for two readers of one file, never share a transcript.
// (A nonce collision test would only detect a broken random source.)
func TestFreshWrap(t *testing.T) {
	type user struct {
		name    upspin.UserName
		packing upspin.Packing
	}
	for _, u := range []user{{"joe@upspin.io", upspin.EEPack}, {pqJoe, upspin.EEPQPack}} {
		cfg, packer := setupPacking(u.name, u.packing)
		seenPoint := make(map[string]bool)
		seenEncap := make(map[string]bool)
		for i := 0; i < 8; i++ {
			name := upspin.PathName(fmt.Sprintf("%s/fresh/%d", u.name, i))
			d := &upspin.DirEntry{Name: name, SignedName: name, Writer: u.name}
			packBlob(t, cfg, packer, d, []byte("same text every time"))
			if u.packing == upspin.EEPQPack {
				// Add a second reader so one file has two wraps.
				bobCfg, _ := setupPacking(pqBob, upspin.EEPQPack)
				shareBlob(t, cfg, packer, []upspin.PublicKey{cfg.Factotum().PublicKey(), bobCfg.Factotum().PublicKey()}, &d.Packdata)
			}
			ts, err := ee.WrapTranscripts(d.Packdata, u.packing)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range ts {
				if len(w.Ephemeral) == 0 {
					t.Fatalf("%s: wrap without an ephemeral point", u.packing)
				}
				if seenPoint[string(w.Ephemeral)] {
					t.Fatalf("%s: ephemeral point reused across wraps", u.packing)
				}
				seenPoint[string(w.Ephemeral)] = true
				if u.packing == upspin.EEPQPack {
					if len(w.Encap) == 0 {
						t.Fatalf("eepq: wrap without an ML-KEM ciphertext")
					}
					if seenEncap[string(w.Encap)] {
						t.Fatalf("eepq: ML-KEM ciphertext reused across wraps")
					}
					seenEncap[string(w.Encap)] = true
				}
			}
		}
	}
}

// mixedFactotum answers ECDH with one user's key and ML-KEM with another's,
// to check that a wrapped key needs both halves of the right key.
type mixedFactotum struct {
	upspin.Factotum
	kem     factotum.Decapsulator
	kemHash []byte
}

func (m mixedFactotum) Decapsulate(keyHash, ciphertext []byte) ([]byte, error) {
	return m.kem.Decapsulate(m.kemHash, ciphertext)
}

// TestCrossKeyPQ checks that a key wrapped for pqjoe cannot be unwrapped
// with pqbob's keys, nor with pqjoe's ECDH key and pqbob's ML-KEM key.
func TestCrossKeyPQ(t *testing.T) {
	const (
		name = upspin.PathName(pqJoe + "/crosskey")
		text = "for pqjoe only"
	)
	joeCfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	bobCfg, _ := setupPacking(pqBob, upspin.EEPQPack)
	d := &upspin.DirEntry{Name: name, SignedName: name, Writer: pqJoe}
	packBlob(t, joeCfg, packer, d, []byte(text))

	// pqbob, given a wrapped key relabeled with his own key hash.
	relabeled := *d
	relabeled.Packdata = append([]byte(nil), d.Packdata...)
	if err := ee.RelabelWrap(&relabeled.Packdata, upspin.EEPQPack, factotum.KeyHash(bobCfg.Factotum().PublicKey())); err != nil {
		t.Fatal(err)
	}
	if _, err := packer.Unpack(bobCfg, &relabeled); err == nil {
		t.Error("pqbob unwrapped a key made for pqjoe")
	}

	// pqjoe's ECDH key with pqbob's ML-KEM key.
	mixed := mixedFactotum{
		Factotum: joeCfg.Factotum(),
		kem:      bobCfg.Factotum().(factotum.Decapsulator),
		kemHash:  factotum.KeyHash(bobCfg.Factotum().PublicKey()),
	}
	mixedCfg := config.SetFactotum(joeCfg, mixed)
	if _, err := packer.Unpack(mixedCfg, d); err == nil {
		t.Error("unwrapped with the right ECDH key and the wrong ML-KEM key")
	}
	// And the unmodified entry still opens for pqjoe.
	if _, err := packer.Unpack(joeCfg, d); err != nil {
		t.Errorf("pqjoe cannot unpack own file: %v", err)
	}
}

// TestUnpackWithoutDecapsulator checks the error when the factotum has no
// ML-KEM support, as an out-of-tree Factotum implementation may not.
func TestUnpackWithoutDecapsulator(t *testing.T) {
	const name = upspin.PathName(pqJoe + "/nodecap")
	cfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	d := &upspin.DirEntry{Name: name, SignedName: name, Writer: pqJoe}
	packBlob(t, cfg, packer, d, []byte("text"))
	plain := struct{ upspin.Factotum }{cfg.Factotum()} // hides Decapsulate
	if _, err := packer.Unpack(config.SetFactotum(cfg, plain), d); !errors.Is(errors.Invalid, err) {
		t.Errorf("Unpack without Decapsulator: got %v, want Invalid", err)
	}
}

// TestEEPQDisabledByDefault checks that every operation of the eepq packer
// fails until the -eepq flag enables it, and that ee is unaffected.
// It flips the process-wide packing switch, so it must not call
// t.Parallel and no other test in the package may run alongside it.
func TestEEPQDisabledByDefault(t *testing.T) {
	const name = upspin.PathName(pqJoe + "/disabled")
	cfg, packer := setupPacking(pqJoe, upspin.EEPQPack)
	d := &upspin.DirEntry{Name: name, SignedName: name, Writer: pqJoe}
	packBlob(t, cfg, packer, d, []byte("text"))

	ee.SetEEPQEnabled(false)
	defer ee.SetEEPQEnabled(true)
	if _, err := packer.Pack(cfg, d); !errors.Is(errors.Permission, err) {
		t.Errorf("Pack while disabled: got %v, want Permission", err)
	} else if !strings.Contains(err.Error(), filepath.Base(os.Args[0])) {
		t.Errorf("Pack while disabled: error does not name the process: %v", err)
	}
	if _, err := packer.Unpack(cfg, d); !errors.Is(errors.Permission, err) {
		t.Errorf("Unpack while disabled: got %v, want Permission", err)
	}
	if _, err := packer.ReaderHashes(d.Packdata); !errors.Is(errors.Permission, err) {
		t.Errorf("ReaderHashes while disabled: got %v, want Permission", err)
	}
	if err := packer.Name(cfg, d, name+".2"); !errors.Is(errors.Permission, err) {
		t.Errorf("Name while disabled: got %v, want Permission", err)
	}
	pd := []*[]byte{&d.Packdata}
	packer.Share(cfg, []upspin.PublicKey{cfg.Factotum().PublicKey()}, pd)
	if pd[0] != nil {
		t.Errorf("Share while disabled did not skip the packdata")
	}
	if _, _, err := ee.CreateKeys("p256+mlkem768", make([]byte, 32)); !errors.Is(errors.Permission, err) {
		t.Errorf("CreateKeys of a post-quantum key while disabled: got %v, want Permission", err)
	}
	// Classic ee keeps working.
	classicCfg, classic := setupPacking("joe@upspin.io", upspin.EEPack)
	testPackAndUnpack(t, classicCfg, classic, "joe@upspin.io/still/works", []byte("classic"))
}

// TestTamperMatrix flips the first and the last bit of every packdata
// field and checks that every operation that parses the bytes rejects the
// result: Unpack, Name, SetTime and Countersign, under both packings, on
// an entry with one reader, one with two readers (each wrap tampered in
// turn) and one shared with all users (whose clear dkey is signed).
// sig2 is the exception by design: it is a fallback signature consulted
// only when sig fails, so damage to it changes nothing while sig is
// intact; a final case checks that damage to both is rejected.
func TestTamperMatrix(t *testing.T) {
	type user struct {
		name, other, rotated upspin.UserName
		packing              upspin.Packing
	}
	users := []user{
		{"joe@upspin.io", "bob@upspin.io", "joe2", upspin.EEPack},
		{pqJoe, pqBob, "pqjoe2", upspin.EEPQPack},
	}
	for _, u := range users {
		cfg, packer := setupPacking(u.name, u.packing)
		otherCfg, _ := setupPacking(u.other, u.packing)
		f2, err := factotum.NewFromDir(testutil.Repo("key", "testdata", string(u.rotated)))
		if err != nil {
			t.Fatal(err)
		}
		self := cfg.Factotum().PublicKey()

		// Three shapes of entry.
		type shape struct {
			label   string
			readers []upspin.PublicKey // nil: leave the packer's own wraps
		}
		shapes := []shape{
			{"one reader", nil},
			{"two readers", []upspin.PublicKey{self, otherCfg.Factotum().PublicKey()}},
			{"all users", []upspin.PublicKey{self, upspin.AllUsersKey}},
		}
		fields := []string{"sig", "sig2", "keyHash", "dkey", "nonce", "ephemeral.X", "ephemeral.Y", "blockSum"}
		if u.packing == upspin.EEPQPack {
			fields = append(fields, "encap")
		}
		// The operations that parse and check the packdata.
		ops := map[string]func(e *upspin.DirEntry) error{
			"Unpack": func(e *upspin.DirEntry) error { _, err := packer.Unpack(cfg, e); return err },
			"Name":   func(e *upspin.DirEntry) error { return packer.Name(cfg, e, e.Name+".renamed") },
			"SetTime": func(e *upspin.DirEntry) error {
				return packer.SetTime(cfg, e, e.Time+1)
			},
			"Countersign": func(e *upspin.DirEntry) error { return packer.Countersign(self, f2, e) },
		}
		for _, sh := range shapes {
			name := upspin.PathName(fmt.Sprintf("%s/tamper/%s", u.name, strings.ReplaceAll(sh.label, " ", "-")))
			d := &upspin.DirEntry{Name: name, SignedName: name, Writer: u.name, Time: 1725700000}
			cipher := packBlob(t, cfg, packer, d, []byte("tamper matrix"))
			if sh.readers != nil {
				shareBlob(t, cfg, packer, sh.readers, &d.Packdata)
			}
			hashes, err := packer.ReaderHashes(d.Packdata)
			if err != nil {
				t.Fatal(err)
			}
			for wrap := range hashes {
				// Each wrap is checked through the reader it belongs to:
				// the owner runs every operation on its own wrap, and
				// the other reader (or a user with no wrap, through the
				// all-users wrap) unpacks with theirs. A wrap for one
				// reader is not authenticated to another by design, so
				// damage to it must leave the others unaffected, which
				// the untouched-entry checks below confirm.
				allUsers := bytes.Equal(hashes[wrap], factotum.AllUsersKeyHash)
				ownWrap := bytes.Equal(hashes[wrap], factotum.KeyHash(self))
				wrapOps := ops
				if !ownWrap {
					wrapOps = map[string]func(e *upspin.DirEntry) error{
						"Unpack as " + string(u.other): func(e *upspin.DirEntry) error { _, err := packer.Unpack(otherCfg, e); return err },
					}
				}
				for _, field := range fields {
					if allUsers && (field == "nonce" || field == "ephemeral.X" || field == "ephemeral.Y" || field == "encap") {
						continue // the all-users wrap has none of these
					}
					for _, last := range []bool{false, true} {
						for opName, op := range wrapOps {
							e := *d
							e.Packdata = append([]byte(nil), d.Packdata...)
							if err := ee.Tamper(&e.Packdata, u.packing, field, last, wrap); err != nil {
								t.Fatalf("%s %s wrap %d %s: %v", u.packing, sh.label, wrap, field, err)
							}
							err := op(&e)
							if field == "sig2" {
								if err != nil {
									t.Errorf("%s %s: %s with tampered sig2 and intact sig: got %v, want success", u.packing, sh.label, opName, err)
								}
								continue
							}
							if sh.label == "all users" && ownWrap && field == "keyHash" && opName != "Countersign" {
								// With its own key hash damaged, the owner
								// falls through to the all-users wrap, which
								// grants everyone the clear file key; that is
								// the wrap's purpose, so the operation succeeds.
								// Countersign looks for the old key's wrap by
								// hash and does not.
								if err != nil {
									t.Errorf("%s %s: %s with a damaged own key hash should fall back to the all-users wrap: %v", u.packing, sh.label, opName, err)
								}
								continue
							}
							if err == nil {
								t.Errorf("%s %s wrap %d: %s accepted tampered %s (last=%t)", u.packing, sh.label, wrap, opName, field, last)
							}
						}
					}
				}
			}
			// Both signatures damaged.
			e := *d
			e.Packdata = append([]byte(nil), d.Packdata...)
			for _, field := range []string{"sig", "sig2"} {
				if err := ee.Tamper(&e.Packdata, u.packing, field, false, 0); err != nil {
					t.Fatal(err)
				}
			}
			for opName, op := range ops {
				if err := op(&e); err == nil {
					t.Errorf("%s %s: %s accepted tampered sig and sig2", u.packing, sh.label, opName)
				}
			}
			// The untouched entry still passes every operation, for the
			// owner and, where it has a wrap, for the other reader.
			if got := unpackBlob(t, cfg, packer, d, cipher); string(got) != "tamper matrix" {
				t.Errorf("%s %s: untouched entry unpacked to %q", u.packing, sh.label, got)
			}
			if sh.readers != nil {
				if got := unpackBlob(t, otherCfg, packer, d, cipher); string(got) != "tamper matrix" {
					t.Errorf("%s %s: untouched entry unpacked by %s to %q", u.packing, sh.label, u.other, got)
				}
			}
			for opName, op := range ops {
				e := *d
				e.Packdata = append([]byte(nil), d.Packdata...)
				if err := op(&e); err != nil {
					t.Errorf("%s %s: %s on the untouched entry: %v", u.packing, sh.label, opName, err)
				}
			}
		}
	}
}

// TestConfusion checks that mismatched packings, curves, ciphertext sizes
// and keys are rejected with an error rather than accepted or a panic.
func TestConfusion(t *testing.T) {
	joeCfg, eePacker := setupPacking("joe@upspin.io", upspin.EEPack)
	pqCfg, pqPacker := setupPacking(pqJoe, upspin.EEPQPack)

	eeEntry := &upspin.DirEntry{Name: "joe@upspin.io/confusion", SignedName: "joe@upspin.io/confusion", Writer: "joe@upspin.io"}
	packBlob(t, joeCfg, eePacker, eeEntry, []byte("ee"))
	pqEntry := &upspin.DirEntry{Name: upspin.PathName(pqJoe + "/confusion"), SignedName: upspin.PathName(pqJoe + "/confusion"), Writer: pqJoe}
	packBlob(t, pqCfg, pqPacker, pqEntry, []byte("eepq"))

	// An eepq packdata presented as ee, and the reverse.
	asEE := *pqEntry
	asEE.Packing = upspin.EEPack
	if _, err := eePacker.Unpack(pqCfg, &asEE); err == nil {
		t.Error("eepq packdata was accepted as ee")
	}
	asPQ := *eeEntry
	asPQ.Packing = upspin.EEPQPack
	if _, err := pqPacker.Unpack(joeCfg, &asPQ); err == nil {
		t.Error("ee packdata was accepted as eepq")
	}

	// An ephemeral point on P-521 against a P-256 reader.
	for _, c := range []struct {
		cfg    upspin.Config
		packer upspin.Packer
		entry  *upspin.DirEntry
	}{{joeCfg, eePacker, eeEntry}, {pqCfg, pqPacker, pqEntry}} {
		e := *c.entry
		e.Packdata = append([]byte(nil), c.entry.Packdata...)
		if err := ee.ReplaceEphemeral(&e.Packdata, c.packer.Packing(), elliptic.P521()); err != nil {
			t.Fatal(err)
		}
		if _, err := c.packer.Unpack(c.cfg, &e); err == nil {
			t.Errorf("%s: ephemeral point on the wrong curve was accepted", c.packer)
		}
	}

	// An ML-KEM-1024 sized ciphertext against an ML-KEM-768 key.
	e := *pqEntry
	e.Packdata = append([]byte(nil), pqEntry.Packdata...)
	if err := ee.ResizeEncap(&e.Packdata, upspin.EEPQPack, mlkem.CiphertextSize1024); err != nil {
		t.Fatal(err)
	}
	if _, err := pqPacker.Unpack(pqCfg, &e); !errors.Is(errors.Invalid, err) {
		t.Errorf("ML-KEM-1024 ciphertext against ML-KEM-768 key: got %v, want Invalid", err)
	}
	// A ciphertext of a size that is no ML-KEM size fails to parse at all.
	e = *pqEntry
	e.Packdata = append([]byte(nil), pqEntry.Packdata...)
	if err := ee.ResizeEncap(&e.Packdata, upspin.EEPQPack, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := pqPacker.Unpack(pqCfg, &e); !errors.Is(errors.Invalid, err) {
		t.Errorf("ML-KEM ciphertext of 1000 bytes: got %v, want Invalid", err)
	}
}

// TestPackdataSizes pins the Packdata size of a one-reader entry for each
// key type, the operational cost of the packings that the docs quote.
func TestPackdataSizes(t *testing.T) {
	cases := []struct {
		name    upspin.UserName
		packing upspin.Packing
		want    int
	}{
		{"joe@upspin.io", upspin.EEPack, sizeEEP256},
		{pqJoe, upspin.EEPQPack, sizeEEPQP256},
		{pqBob, upspin.EEPQPack, sizeEEPQP521},
	}
	for _, c := range cases {
		cfg, packer := setupPacking(c.name, c.packing)
		name := upspin.PathName(c.name + "/size")
		d := &upspin.DirEntry{Name: name, SignedName: name, Writer: c.name}
		packBlob(t, cfg, packer, d, []byte("size"))
		// The constants are the largest sizes. Signature and point
		// integers are encoded without leading zeros, so each may be a
		// byte shorter: rarely on P-256, and half the time on P-521,
		// whose 521 bit values are 65 or 66 bytes. Four such integers
		// give a spread of four bytes; eight is a safe margin.
		if got := len(d.Packdata); got > c.want || got < c.want-8 {
			t.Errorf("%s %s: Packdata is %d bytes, want %d", c.name, c.packing, got, c.want)
		}
	}
}

// Largest Packdata sizes of a one-reader entry, checked by
// TestPackdataSizes: ee with a p256 key, eepq with p256+mlkem768, and eepq
// with p521+mlkem1024. The signature, empty second signature, count and
// block checksum take 102 bytes with P-256 and 170 with P-521. Each reader
// adds a wrapped key: 161 bytes for ee with P-256, 1251 for eepq with
// p256+mlkem768 (the 1088 byte ML-KEM-768 ciphertext and its length), and
// 1803 for eepq with p521+mlkem1024 (a 1568 byte ciphertext).
const (
	sizeEEP256   = 263
	sizeEEPQP256 = 1353
	sizeEEPQP521 = 1973
)
