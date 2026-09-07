// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ee implements an elliptic-curve end-to-end encryption packer.
// It registers two packings that share all code except key wrapping:
// EEPack wraps the file key for each reader with ECDH, and EEPQPack wraps
// it with a hybrid of ECDH and ML-KEM so that the wrapping also resists a
// quantum attacker.
package ee

// Upspin ee crypto summary:
// Alice shares a file with Bob by picking a new random symmetric key, encrypting the file,
// wrapping the symmetric encryption key with Bob's public key, signing the file using
// her own elliptic curve private key, and sending the ciphertext to a storage server
// and metadata to a directory server.
//
// Under EEPQPack the wrapping step also encapsulates a second shared secret
// to Bob's ML-KEM encapsulation key, and the two secrets are combined by HKDF.
// Recovering the file key then needs both the ECDH and the ML-KEM secret.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"

	"upspin.io/bind"
	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/log"
	"upspin.io/pack"
	"upspin.io/pack/internal"
	"upspin.io/pack/packutil"
	"upspin.io/path"
	"upspin.io/upspin"
)

type keyHashArray [sha256.Size]byte // sometimes we need the array

var _ upspin.Packer = ee{}

// ee is the packer for EEPack and EEPQPack. The packing field selects the
// key wrapping scheme and the Packdata wire format; everything else is
// shared.
type ee struct {
	packing upspin.Packing
}

const (
	aesKeyLen            = 32 // AES-256 because public cloud should withstand multifile multikey attack.
	marshalBufLen        = 66 // big enough for p521 according to (c.curve.Params().BitSize + 7) >> 3
	gcmStandardNonceSize = 12
	gcmTagSize           = 16
)

func init() {
	pack.Register(ee{packing: upspin.EEPack})
	pack.Register(ee{packing: upspin.EEPQPack})
	// EEPQPack is opt-in; see SetEEPQEnabled.
	pack.SetEnabled(upspin.EEPQPack, false)
}

// EEPQPack is opt-in. It is off by default and turned on by the -eepq
// command line flag (see upspin.io/flags), so that the post-quantum
// packing and its wire format stay opt-in until they have had more
// review. The state lives in the pack registry, pack.Enabled, and nowhere
// else. While it is off, every operation of this packer fails with an
// error that names the flag, config parsing refuses "packing: eepq",
// valid.DirEntry refuses entries in the packing (so a directory server
// rejects them), and CreateKeys refuses post-quantum key types.
//
// The flag does not contain the key format: a post-quantum public key has
// four lines, and a binary from before this change cannot parse it at
// all. See doc/security.filmil.md for what must be upgraded before a user
// rotates to a post-quantum key.

// SetEEPQEnabled turns the EEPQPack packing and post-quantum key generation
// on or off for this process. The -eepq flag calls it; tests may too. The
// gate is advisory: any code in the process can call it.
func SetEEPQEnabled(on bool) { pack.SetEnabled(upspin.EEPQPack, on) }

// EEPQEnabled reports whether the EEPQPack packing is enabled.
func EEPQEnabled() bool { return pack.Enabled(upspin.EEPQPack) }

// errEEPQDisabled returns the error for an operation on EEPQPack while it
// is disabled. It names the process, since the error may be produced on a
// server and shown to a user whose own client was started with the flag;
// naming the flag alone would send that user to the wrong machine.
func errEEPQDisabled() error {
	return errors.E(errors.Permission, errors.Errorf("the eepq packing is disabled in this %s process; start it with the -eepq flag", processName()))
}

// processName returns the base name of the running program, for error
// messages that must say which process lacks a flag.
func processName() string {
	if len(os.Args) == 0 {
		return "unknown"
	}
	return filepath.Base(os.Args[0])
}

// checkEnabled returns errEEPQDisabled for an EEPQPack packer that has not
// been enabled, and nil otherwise.
func (ee ee) checkEnabled() error {
	if ee.packing == upspin.EEPQPack && !EEPQEnabled() {
		return errEEPQDisabled()
	}
	return nil
}

var (
	errVerify           = errors.Str("does not verify")
	errWriter           = errors.Str("empty Writer in Metadata")
	errNoWrappedKey     = errors.Str("no wrapped key for me")
	errKeyLength        = errors.Str("wrong key length for AES-256")
	errSignedNameNotSet = errors.Str("empty SignedName")
)

var errNotOnCurve = errors.Str("a crypto attack was attempted against you; see safecurves.cr.yp.to/twist.html for details")

func (ee ee) Packing() upspin.Packing {
	return ee.packing
}

func (ee ee) PackLen(cfg upspin.Config, cleartext []byte, d *upspin.DirEntry) int {
	if err := pack.CheckPacking(ee, d); err != nil {
		return -1
	}
	return len(cleartext)
}

func (ee ee) UnpackLen(cfg upspin.Config, ciphertext []byte, d *upspin.DirEntry) int {
	if err := pack.CheckPacking(ee, d); err != nil {
		return -1
	}
	return len(ciphertext)
}

func (ee ee) String() string {
	return ee.packing.String()
}

func (ee ee) Pack(cfg upspin.Config, d *upspin.DirEntry) (upspin.BlockPacker, error) {
	const op errors.Op = "pack/ee.Pack"
	if err := ee.checkEnabled(); err != nil {
		return nil, errors.E(op, d.Name, err)
	}
	if err := pack.CheckPacking(ee, d); err != nil {
		return nil, errors.E(op, errors.Invalid, d.Name, err)
	}
	if len(d.SignedName) == 0 {
		return nil, errors.E(op, errors.Invalid, d.Name, errSignedNameNotSet)
	}

	// TODO(adg): support append; for now assume a new file.
	d.Blocks = nil

	dkey, blockCipher, err := newKeyAndCipher()
	if err != nil {
		return nil, errors.E(op, d.Name, err)
	}

	return &blockPacker{
		packer: ee,
		cfg:    cfg,
		entry:  d,
		cipher: blockCipher,
		dkey:   dkey,
	}, nil
}

func newKeyAndCipher() ([]byte, cipher.Block, error) {
	// Pick fresh file encryption key.
	dkey := make([]byte, aesKeyLen)
	_, err := rand.Read(dkey)
	if err != nil {
		return nil, nil, err
	}
	// This shouldn't happen, but be paranoid.
	if len(dkey) != aesKeyLen {
		return nil, nil, errKeyLength
	}

	// Set up the block cipher.
	blockCipher, err := aes.NewCipher(dkey)
	if err != nil {
		return nil, nil, err
	}

	return dkey, blockCipher, nil
}

type blockPacker struct {
	packer ee
	cfg    upspin.Config
	entry  *upspin.DirEntry
	cipher cipher.Block
	dkey   []byte

	buf internal.LazyBuffer
}

func (bp *blockPacker) Pack(cleartext []byte) (ciphertext []byte, err error) {
	const op errors.Op = "pack/ee.blockPacker.Pack"
	if err := internal.CheckLocationSet(bp.entry); err != nil {
		return nil, err
	}

	// Compute offset of this block,
	// the size of the preceding blocks.
	offs, err := bp.entry.Size()
	if err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}

	// Encrypt.
	ciphertext = bp.buf.Bytes(len(cleartext))
	if err := crypt(ciphertext, cleartext, bp.cipher, offs); err != nil {
		return nil, errors.E(op, err)
	}

	// Compute size and checksum.
	size := int64(len(ciphertext))
	b := sha256.Sum256(ciphertext)
	sum := b[:]

	// Create and append new DirBlock record.
	block := upspin.DirBlock{
		Size:     size,
		Offset:   offs,
		Packdata: sum,
	}
	bp.entry.Blocks = append(bp.entry.Blocks, block)

	return ciphertext, nil
}

func (bp *blockPacker) SetLocation(l upspin.Location) {
	bs := bp.entry.Blocks
	bs[len(bs)-1].Location = l
}

func (bp *blockPacker) Close() error {
	const op errors.Op = "pack/ee.blockPacker.Close"
	// Zero out encryption key when we're done.
	defer zeroSlice(&bp.dkey)

	if err := internal.CheckLocationSet(bp.entry); err != nil {
		return err
	}

	name := bp.entry.SignedName
	cfg := bp.cfg
	var pd packdata

	// Wrap keys.
	pd.wrap = make([]wrappedKey, 1, 2)

	// First, wrap for myself.
	rp := cfg.Factotum().PublicKey()
	p, err := factotum.ParsePublicKey(rp)
	if err != nil {
		return errors.E(op, name, err)
	}
	pd.wrap[0], err = bp.packer.wrap(rp, p, bp.dkey)
	if err != nil {
		return errors.E(op, name, err)
	}

	// Also wrap for owner, if different.
	parsed, err := path.Parse(name)
	if err != nil {
		return errors.E(op, name, err)
	}
	owner := parsed.User()
	if owner != cfg.UserName() {
		keyServer, err := bind.KeyServer(cfg, cfg.KeyEndpoint())
		if err != nil {
			return errors.E(op, name, err)
		}
		u, err := keyServer.Lookup(owner)
		if err != nil {
			return errors.E(op, name, owner, err)
		}
		ownerKey := u.PublicKey
		if ownerKey == cfg.Factotum().PublicKey() {
			log.Debug.Printf("pack/ee: %q and %q have the same keys", owner, cfg.UserName())
		} else {
			p, err = factotum.ParsePublicKey(ownerKey)
			if err != nil {
				return errors.E(op, name, owner, err)
			}
			wrap, err := bp.packer.wrap(ownerKey, p, bp.dkey)
			if err != nil {
				return errors.E(op, name, owner, err)
			}
			pd.wrap = append(pd.wrap, wrap)
		}
	}

	// Compute checksum of block hashes.
	pd.blockSum = internal.BlockSum(bp.entry.Blocks)

	// Compute entry signature.
	f := bp.cfg.Factotum()
	e := bp.entry
	pd.sig, err = f.FileSign(f.DirEntryHash(e.SignedName, e.Link, e.Attr, e.Packing, e.Time, bp.dkey, pd.blockSum))
	if err != nil {
		return errors.E(op, err)
	}
	return pd.Marshal(&bp.entry.Packdata, bp.packer.packing)
}

func (ee ee) Unpack(cfg upspin.Config, d *upspin.DirEntry) (upspin.BlockUnpacker, error) {
	const op errors.Op = "pack/ee.Unpack"
	if err := ee.checkEnabled(); err != nil {
		return nil, errors.E(op, d.Name, err)
	}
	if err := pack.CheckPacking(ee, d); err != nil {
		return nil, errors.E(op, errors.Invalid, d.Name, err)
	}

	// Call Size to check that the block Offsets and Sizes are consistent.
	if _, err := d.Size(); err != nil {
		return nil, errors.E(op, d.Name, err)
	}

	var pd packdata
	if err := pd.Unmarshal(d.Packdata, ee.packing); err != nil {
		return nil, errors.E(op, d.Name, err)
	}

	// Check that our stored+signed block checksum matches the sum of the actual blocks.
	if !bytes.Equal(internal.BlockSum(d.Blocks), pd.blockSum) {
		return nil, errors.E(op, d.Name, "checksum mismatch")
	}

	// Fetch writer public key.
	writer := d.Writer
	if len(writer) == 0 {
		return nil, errors.E(op, d.Name, errWriter)
	}
	writerRawPubKey, err := packutil.GetPublicKey(cfg, writer)
	if err != nil {
		return nil, errors.E(op, writer, err)
	}
	writerPubKey, err := factotum.ParsePublicKey(writerRawPubKey)
	if err != nil {
		return nil, errors.E(op, writer, err)
	}

	// Pull the decryption key out of the wrapped keys.
	// For quick lookup, hash my public key and locate my wrapped key in the metadata.
	me := cfg.UserName()
	f := cfg.Factotum()
	rhash := factotum.KeyHash(f.PublicKey())
	for _, w := range pd.wrap {
		all := bytes.Equal(factotum.AllUsersKeyHash, w.keyHash)
		if !all && !bytes.Equal(rhash, w.keyHash) {
			continue
		}
		var dkey []byte
		if all {
			dkey = w.dkey
		} else {
			// Decode my wrapped key using my private key.
			dkey, err = aesUnwrap(ee.packing, f, w)
			if err != nil {
				return nil, errors.E(op, d.Name, me, err)
			}
		}
		if len(dkey) != aesKeyLen {
			return nil, errors.E(op, d.Name, errKeyLength)
		}
		// Verify that this was signed with the writer's old or new public key.
		vhash := f.DirEntryHash(d.SignedName, d.Link, d.Attr, d.Packing, d.Time, dkey, pd.blockSum)
		if !ecdsa.Verify(writerPubKey, vhash, pd.sig.R, pd.sig.S) &&
			!ecdsa.Verify(writerPubKey, vhash, pd.sig2.R, pd.sig2.S) {
			// Check sig2 in case writerPubKey is rotating.
			return nil, errors.E(op, d.Name, writer, errVerify)
			// TODO(ehg) If reader is owner, consider trying even older factotum keys.
		}
		blockCipher, err := aes.NewCipher(dkey)
		if err != nil {
			return nil, errors.E(op, err)
		}
		// We're OK to start decrypting blocks.
		return &blockUnpacker{
			cfg:          cfg,
			entry:        d,
			BlockTracker: internal.NewBlockTracker(d.Blocks),
			cipher:       blockCipher,
		}, nil
	}
	return nil, errors.E(op, errors.CannotDecrypt, d.Name, me)
}

type blockUnpacker struct {
	cfg                   upspin.Config
	entry                 *upspin.DirEntry
	internal.BlockTracker // provides NextBlock method and Block field
	cipher                cipher.Block

	buf internal.LazyBuffer
}

func (bp *blockUnpacker) Unpack(ciphertext []byte) (cleartext []byte, err error) {
	const op errors.Op = "pack/ee.blockUnpacker.Unpack"
	// Validate checksum.
	b := sha256.Sum256(ciphertext)
	sum := b[:]
	if got, want := sum, bp.entry.Blocks[bp.Block].Packdata; !bytes.Equal(got, want) {
		return nil, errors.E(op, bp.entry.Name, "checksum mismatch")
	}

	cleartext = bp.buf.Bytes(len(ciphertext))

	// Decrypt.
	if err := crypt(cleartext, ciphertext, bp.cipher, bp.entry.Blocks[bp.Block].Offset); err != nil {
		return nil, errors.E(op, bp.entry.Name, err)
	}

	return cleartext, nil
}

func (bp *blockUnpacker) Close() error {
	return nil
}

// ReaderHashes returns SHA-256 hashes of the public keys able to decrypt the
// associated ciphertext.
func (ee ee) ReaderHashes(pd []byte) (readers [][]byte, err error) {
	const op errors.Op = "pack/ee.ReaderHashes"
	if err := ee.checkEnabled(); err != nil {
		return nil, errors.E(op, err)
	}
	var d packdata
	if err := d.Unmarshal(pd, ee.packing); err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	readers = make([][]byte, len(d.wrap))
	for i := 0; i < len(d.wrap); i++ {
		readers[i] = d.wrap[i].keyHash
	}
	return readers, nil
}

// Share extracts the file decryption key from the packdata, wraps it for a revised list of readers, and updates packdata.
// Under EEPQPack a reader whose key has no ML-KEM component cannot be
// wrapped for and is left out of the new list, with an error logged.
func (ee ee) Share(cfg upspin.Config, readers []upspin.PublicKey, packdataSlice []*[]byte) {
	if err := ee.checkEnabled(); err != nil {
		log.Error.Printf("pack/ee.Share: %v", err)
		for j := range packdataSlice {
			packdataSlice[j] = nil
		}
		return
	}
	// A Packdata holds a cipherSum, a Signature, and a list of wrapped keys.
	// Share updates the wrapped keys, leaving the other two fields unchanged.
	// For efficiency, Share() reuses the wrapped key for readers common to the old and new lists.

	// Fetch all the public keys we'll need.
	pubkey := make([]*ecdsa.PublicKey, len(readers))
	hash := make([]keyHashArray, len(readers))
	for i, pub := range readers {
		if pub == upspin.AllUsersKey {
			copy(hash[i][:], factotum.AllUsersKeyHash)
			continue
		}
		var err error
		pubkey[i], err = factotum.ParsePublicKey(pub)
		if err != nil {
			continue
		}
		copy(hash[i][:], factotum.KeyHash(pub))
	}

	// For each packdata, wrap for new readers.
	for j, d := range packdataSlice {
		// Extract dkey and existing wrapped keys from packdata.
		var dkey []byte
		alreadyWrapped := make(map[keyHashArray]*wrappedKey)
		var pd packdata
		if err := pd.Unmarshal(*d, ee.packing); err != nil {
			log.Error.Printf("pack/ee.Share: packdata unmarshal failed: %v", err)
			for jj := j; jj < len(packdataSlice); jj++ {
				packdataSlice[jj] = nil
			}
			return
		}
		for i, w := range pd.wrap {
			var h keyHashArray
			copy(h[:], w.keyHash)
			alreadyWrapped[h] = &pd.wrap[i]
			if bytes.Equal(factotum.AllUsersKeyHash, w.keyHash) {
				dkey = w.dkey
			} else {
				_, err := cfg.Factotum().PublicKeyFromHash(w.keyHash)
				if err != nil {
					// to unwrap dkey, we can only use our own private keys
					continue
				}
				dkey, err = aesUnwrap(ee.packing, cfg.Factotum(), w)
				if err != nil {
					log.Error.Printf("pack/ee: dkey unwrap failed: %v", err)
					break
				}
			}
		}
		if len(dkey) == 0 { // Failed to get a valid decryption key.
			packdataSlice[j] = nil // Tell caller this packdata was skipped.
			continue
		}

		// Create new list of wrapped keys.
		pd.wrap = make([]wrappedKey, 0, len(readers))
		for i := range readers {
			if pubkey[i] == nil {
				if bytes.Equal(factotum.AllUsersKeyHash, hash[i][:]) {
					// If readable by anyone,
					// store the dkey unwrapped.
					pd.wrap = append(pd.wrap, wrappedKey{
						keyHash: factotum.AllUsersKeyHash,
						dkey:    dkey,
					})
				}
				continue
			}
			pw, ok := alreadyWrapped[hash[i]]
			if !ok { // then need to wrap
				w, err := ee.wrap(readers[i], pubkey[i], dkey)
				if err != nil {
					log.Error.Printf("pack/ee.Share: cannot wrap for reader with key hash %x: %v", hash[i][:4], err)
					continue
				}
				pw = &w
			} // else reuse the existing wrapped dkey.
			pd.wrap = append(pd.wrap, *pw)
		}

		// Rebuild packdataSlice[j] from existing sig and new wrapped keys.
		var dst []byte
		if pd.Marshal(&dst, ee.packing) != nil {
			packdataSlice[j] = nil // Tell caller this packdata was skipped.
		} else {
			*packdataSlice[j] = dst
		}
	}
}

// Name implements upspin.Name.
func (ee ee) Name(cfg upspin.Config, d *upspin.DirEntry, newName upspin.PathName) error {
	const op errors.Op = "pack/ee.Name"
	return ee.updateDirEntry(op, cfg, d, newName, d.Time)
}

// SetTime implements upspin.SetTime.
func (ee ee) SetTime(cfg upspin.Config, d *upspin.DirEntry, t upspin.Time) error {
	const op errors.Op = "pack/ee.SetTime"
	return ee.updateDirEntry(op, cfg, d, d.Name, t)
}

func (ee ee) updateDirEntry(op errors.Op, cfg upspin.Config, d *upspin.DirEntry, newName upspin.PathName, newTime upspin.Time) error {
	if err := ee.checkEnabled(); err != nil {
		return errors.E(op, d.Name, err)
	}
	parsed, err := path.Parse(d.Name)
	if err != nil {
		return errors.E(op, err)
	}
	parsedNew, err := path.Parse(newName)
	if err != nil {
		return errors.E(op, err)
	}
	newName = parsedNew.Path()

	if d.IsDir() && !parsed.Equal(parsedNew) {
		return errors.E(op, d.Name, errors.IsDir, "cannot rename directory")
	}
	if err := pack.CheckPacking(ee, d); err != nil {
		return errors.E(op, errors.Invalid, d.Name, err)
	}

	var pd packdata
	if err := pd.Unmarshal(d.Packdata, ee.packing); err != nil {
		return errors.E(op, errors.Invalid, d.Name, err)
	}

	// The writer has a well-known public key.
	writerRawPubKey, err := packutil.GetPublicKey(cfg, d.Writer)
	if err != nil {
		return errors.E(op, d.Name, err)
	}
	writerPubKey, err := factotum.ParsePublicKey(writerRawPubKey)
	if err != nil {
		return errors.E(op, d.Name, err)
	}

	// Now get my own keys.
	me := cfg.UserName() // Recipient of the file is me (the user in the config)
	rawPublicKey, err := packutil.GetPublicKey(cfg, me)
	if err != nil {
		return errors.E(op, d.Name, err)
	}

	// For quick lookup, hash my public key and locate my wrapped key (or
	// the AllUsersKeyHash) in the metadata.
	rhash := factotum.KeyHash(rawPublicKey)
	allFound := false
	wrapFound := false
	var w wrappedKey
	for _, w = range pd.wrap {
		if bytes.Equal(rhash, w.keyHash) {
			wrapFound = true
			break
		}
		if bytes.Equal(factotum.AllUsersKeyHash, w.keyHash) {
			allFound = true
			break
		}
	}
	if !wrapFound && !allFound {
		return errors.E(op, errors.NotExist, d.Name, errNoWrappedKey)
	}

	f := cfg.Factotum()
	var dkey []byte
	if allFound {
		dkey = w.dkey
	} else {
		// Decode my wrapped key using my private key
		dkey, err = aesUnwrap(ee.packing, f, w)
		if err != nil {
			return errors.E(op, errors.CannotDecrypt, d.Name, err)
		}
	}

	// Verify that this was signed with the writer's old or new public key.
	vhash := f.DirEntryHash(d.SignedName, d.Link, d.Attr, d.Packing, d.Time, dkey, pd.blockSum)
	if !ecdsa.Verify(writerPubKey, vhash, pd.sig.R, pd.sig.S) &&
		!ecdsa.Verify(writerPubKey, vhash, pd.sig2.R, pd.sig2.S) {
		// Check sig2 in case writerPubKey is rotating.
		return errors.E(op, d.Name, errVerify)
	}

	// If we are changing directories, remove all wrapped keys except my own.
	if !parsed.Drop(1).Equal(parsedNew.Drop(1)) {
		pd.wrap = []wrappedKey{w}
	}

	// Compute new signature.
	d.Writer = cfg.UserName()
	d.SignedName = newName
	d.Time = newTime
	vhash = f.DirEntryHash(d.SignedName, d.Link, d.Attr, d.Packing, d.Time, dkey, pd.blockSum)
	pd.sig, err = f.FileSign(vhash)
	if err != nil {
		return errors.E(op, d.Name, err)
	}

	// Serialize packer metadata. We do not reallocate Packdata since the new data
	// should be the same size or smaller.
	if err := pd.Marshal(&d.Packdata, ee.packing); err != nil {
		return errors.E(op, d.Name, err)
	}
	d.Name = newName

	return nil
}

// Countersign uses the key in factotum f to add a signature to a DirEntry that is already signed by oldKey.
func (ee ee) Countersign(oldKey upspin.PublicKey, f upspin.Factotum, d *upspin.DirEntry) error {
	const op errors.Op = "pack/ee.Countersign"
	if err := ee.checkEnabled(); err != nil {
		return errors.E(op, d.Name, err)
	}
	if d.IsDir() {
		return errors.E(op, d.Name, errors.IsDir, "cannot sign directory")
	}

	// Get ECDSA form of old key.
	oldPubKey, err := factotum.ParsePublicKey(oldKey)
	if err != nil {
		return errors.E(op, d.Name, err)
	}

	// Extract existing signatures, but keep only the newest.
	var pd packdata
	if err := pd.Unmarshal(d.Packdata, ee.packing); err != nil {
		return errors.E(op, d.Name, errors.Invalid, err)
	}

	// Get wrapped key.
	rhash := factotum.KeyHash(oldKey)
	wrapFound := false
	var w wrappedKey
	for _, w = range pd.wrap {
		if bytes.Equal(rhash, w.keyHash) {
			wrapFound = true
			break
		}
	}
	if !wrapFound {
		return errors.E(op, errors.NotExist, d.Name, errNoWrappedKey)
	}
	dkey, err := aesUnwrap(ee.packing, f, w)
	if err != nil {
		return errors.E(op, errors.CannotDecrypt, d.Name, err)
	}

	// Verify existing signature with oldKey.
	vhash := f.DirEntryHash(d.SignedName, d.Link, d.Attr, d.Packing, d.Time, dkey, pd.blockSum)
	if !ecdsa.Verify(oldPubKey, vhash, pd.sig.R, pd.sig.S) {
		return errors.E(op, d.Name, errVerify, "unable to verify existing signature")
	}

	// Sign with newKey.
	sig1, err := f.FileSign(vhash)
	if err != nil {
		return errors.E(op, d.Name, errVerify, "unable to make new signature")
	}
	pd.sig2 = pd.sig
	pd.sig = sig1
	return pd.Marshal(&d.Packdata, ee.packing)
}

func (ee ee) UnpackableByAll(d *upspin.DirEntry) (bool, error) {
	const op errors.Op = "pack/ee.UnpackableByAll"
	if err := ee.checkEnabled(); err != nil {
		return false, errors.E(op, d.Name, err)
	}

	if d.Packing != ee.packing {
		p := pack.Lookup(d.Packing)
		if p == nil {
			return false, errors.E(op, d.Name, errors.Errorf("entry has packing %s, need %s", d.Packing, ee.packing))
		}
		return false, errors.E(op, d.Name, errors.Errorf("entry has packing %s, need %s", p, ee.packing))
	}

	var pd packdata
	if err := pd.Unmarshal(d.Packdata, ee.packing); err != nil {
		return false, errors.E(op, d.Name, err)
	}
	for _, w := range pd.wrap {
		if bytes.Equal(factotum.AllUsersKeyHash, w.keyHash) {
			return true, nil
		}
	}
	return false, nil
}

// wrap encrypts dkey for the holder of the public key pub, whose ECDSA part
// is R. Under EEPack it implements NIST 800-56Ar2; see also RFC6637 §8.
// Under EEPQPack it also encapsulates to the ML-KEM part of pub, and fails
// with errors.NotExist if pub has none. See strongKey for how the two
// shared secrets are combined.
func (ee ee) wrap(pub upspin.PublicKey, R *ecdsa.PublicKey, dkey []byte) (w wrappedKey, err error) {
	// Step 1.  Create shared Diffie-Hellman secret.
	// v, V=vG  ephemeral key pair
	// S = vR   shared point
	curve := R.Curve
	// TODO(ehg)  Confirm that curve is one of our approved curves.
	if !curve.IsOnCurve(R.X, R.Y) {
		err = errNotOnCurve
		return
	}
	v, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return
	}
	sx, sy := curve.ScalarMult(R.X, R.Y, v.D.Bytes())
	S := elliptic.Marshal(curve, sx, sy)
	w.ephemeral = ecdsa.PublicKey{Curve: curve, X: v.X, Y: v.Y}

	// Step 1b (EEPQPack only). Encapsulate a second shared secret K to the
	// reader's ML-KEM key. The ciphertext travels in the wrapped key.
	var K []byte
	if ee.packing == upspin.EEPQPack {
		ek, err := factotum.ParseEncapsulationKey(pub)
		if err != nil {
			return w, err
		}
		K, w.encap = ek.Encapsulate()
	}

	// Step 2.  Convert shared secret to strong secret via HKDF.
	w.nonce = make([]byte, gcmStandardNonceSize)
	_, err = rand.Read(w.nonce)
	if err != nil {
		return
	}
	w.keyHash = factotum.KeyHash(pub)
	Rb, err := marshalPoint(curve, R.X, R.Y)
	if err != nil {
		return
	}
	Vb, err := marshalPoint(curve, v.X, v.Y)
	if err != nil {
		return
	}
	strong, err := strongKey(ee.packing, w, Rb, Vb, S, K)
	if err != nil {
		return
	}

	// Step 3. Encrypt dkey.
	block, err := aes.NewCipher(strong)
	if err != nil {
		return
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	w.dkey = make([]byte, 0, len(dkey)+gcmTagSize)
	w.dkey = aead.Seal(w.dkey, w.nonce, dkey, nil)
	// TODO(ehg) figure out why aead.Seal allocated memory here
	return
}

// eepqLabel is the domain separation label of the EEPQPack key combiner.
const eepqLabel = "upspin.io/pack/ee eepq v1"

// strongKey derives the AES-256 key that seals dkey inside w.
//
// Under EEPack the derivation is unchanged from the original ee design:
// HKDF-SHA256 with the ECDH shared point S as the keying material and
// "packing:keyHash:nonce" as the info string.
//
// Under EEPQPack it is an HKDF concatenation combiner in the style of
// X-Wing (draft-connolly-cfrg-xwing-kem), but it is not X-Wing: it uses a
// NIST curve instead of X25519 and HKDF-SHA256 instead of SHA3-256, and
// has no proof of its own. The keying material is the concatenation of
// the ML-KEM shared secret K, the ECDH shared point S, the ephemeral point
// V, the reader's public point R, the ML-KEM ciphertext held in w and a
// fixed label, each prefixed by its length as a 4 byte big-endian
// integer, so the parse of the keying material is unambiguous whatever
// the sizes. The info string is the same as under EEPack; w.keyHash in it
// is the SHA-256 of the reader's whole public key, so the derived key is
// also bound to the reader's key type. Either secret alone is useless: an
// attacker who breaks ECDH still needs K, and one who breaks ML-KEM still
// needs S.
//
// The HKDF salt is nil in both cases, which makes HKDF-Extract an HMAC
// with a fixed key. That is the same role the unkeyed hash plays in the
// X-Wing combiner, and the keying material is uniformly random when either
// KEM is secure, so no salt is needed.
func strongKey(packing upspin.Packing, w wrappedKey, R, V, S, K []byte) ([]byte, error) {
	var ikm []byte
	switch packing {
	case upspin.EEPack:
		ikm = S
	case upspin.EEPQPack:
		for _, part := range [][]byte{K, S, V, R, w.encap, []byte(eepqLabel)} {
			ikm = binary.BigEndian.AppendUint32(ikm, uint32(len(part)))
			ikm = append(ikm, part...)
		}
	default:
		return nil, errors.Errorf("no key derivation for packing %s", packing)
	}
	mess := []byte(fmt.Sprintf("%02x:%x:%x", packing, w.keyHash, w.nonce))
	hash := sha256.New
	hkdf := hkdf.New(hash, ikm, nil, mess)
	strong := make([]byte, aesKeyLen)
	if _, err := io.ReadFull(hkdf, strong); err != nil {
		return nil, err
	}
	return strong, nil
}

// marshalPoint returns the uncompressed SEC 1 encoding of the point (x, y),
// the same bytes elliptic.Marshal produces, without its panic on a point
// that is not on the curve: a point from stored Packdata must not crash
// the reader. A coordinate that does not fit the curve's field is an
// error, never a silent substitute value.
func marshalPoint(curve elliptic.Curve, x, y *big.Int) ([]byte, error) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if x == nil || y == nil || x.Sign() < 0 || y.Sign() < 0 || x.BitLen() > 8*byteLen || y.BitLen() > 8*byteLen {
		return nil, errNotOnCurve
	}
	b := make([]byte, 1+2*byteLen)
	b[0] = 4 // uncompressed point
	x.FillBytes(b[1 : 1+byteLen])
	y.FillBytes(b[1+byteLen:])
	return b, nil
}

// Extract per-file symmetric key from w.
// If error, len(dkey)==0.
func aesUnwrap(packing upspin.Packing, f upspin.Factotum, w wrappedKey) (dkey []byte, err error) {
	myPub, err := f.PublicKeyFromHash(w.keyHash)
	if err != nil {
		return nil, err
	}
	// Step 1.  Create shared Diffie-Hellman secret.
	// S = rV
	pub, err := factotum.ParsePublicKey(myPub)
	if err != nil {
		return nil, err
	}
	sx, sy, err := f.ScalarMult(w.keyHash, pub.Curve, w.ephemeral.X, w.ephemeral.Y)
	if err != nil {
		return nil, err
	}
	S := elliptic.Marshal(pub.Curve, sx, sy)

	// Step 1b (EEPQPack only). Recover the ML-KEM shared secret K.
	// The ciphertext must have the size of my key's KEM; that is part of
	// the wire format, not something to leave to decapsulation.
	var K []byte
	if packing == upspin.EEPQPack {
		kem, err := factotum.KEMOf(myPub)
		if err != nil {
			return nil, err
		}
		if len(w.encap) != kem.CiphertextSize() {
			return nil, errors.E(errors.Invalid, errors.Errorf("ML-KEM ciphertext of %d bytes for key type with %d byte ciphertexts", len(w.encap), kem.CiphertextSize()))
		}
		dec, ok := f.(factotum.Decapsulator)
		if !ok {
			return nil, errors.E(errors.Invalid, "factotum does not support ML-KEM decapsulation")
		}
		K, err = dec.Decapsulate(w.keyHash, w.encap)
		if err != nil {
			return nil, err
		}
	}

	// Step 2.  Convert shared secret to strong secret via HKDF.
	R, err := marshalPoint(pub.Curve, pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	V, err := marshalPoint(pub.Curve, w.ephemeral.X, w.ephemeral.Y)
	if err != nil {
		return nil, err
	}
	strong, err := strongKey(packing, w, R, V, S, K)
	if err != nil {
		return nil, err
	}

	// Step 3. Decrypt dkey.
	block, err := aes.NewCipher(strong)
	if err != nil {
		return
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	dkey = make([]byte, 0, aesKeyLen)
	dkey, err = aead.Open(dkey, w.nonce, w.dkey, nil)
	if err != nil {
		dkey = dkey[:0]
	}
	return
}

// zeroSlice replaces the contents of the given slice with zeroes.
func zeroSlice(b *[]byte) {
	for i := range *b {
		(*b)[i] = 0
	}
}

// crypt [enc|de]crypts the input bytes into the output slice
// with the provided key for the given DirBlock.
func crypt(out, in []byte, blockCipher cipher.Block, offset int64) error {
	const streamBufferSize = 512  // as defined in $GOROOT/src/crypto/cipher/ctr.go
	bs := blockCipher.BlockSize() // 16 bytes in practice

	// We start with a zero iv because we're certain that the
	// encryption key is random and not reused anywhere.
	iv := make([]byte, bs)

	// Set the initialization vector to whatever it was at the start of the
	// nearest (looking backward) stream buffer.
	ivStart := (offset - (offset % streamBufferSize)) / int64(bs)
	iv[bs-1] = byte(ivStart)
	iv[bs-2] = byte(ivStart >> 8)
	iv[bs-3] = byte(ivStart >> 16)
	iv[bs-4] = byte(ivStart >> 24)
	iv[bs-5] = byte(ivStart >> 32)
	iv[bs-6] = byte(ivStart >> 40)
	iv[bs-7] = byte(ivStart >> 48)
	iv[bs-8] = byte(ivStart >> 56)

	ctr := cipher.NewCTR(blockCipher, iv) // #nosec G407 -- the IV is zero by design; see the comment above: the key is fresh per file and the counter is the block offset.

	// If this offset is not an even multiple of streamBufferSize
	// xor some empty data to synchronize it.
	if n := int(offset % streamBufferSize); n > 0 {
		ignore := make([]byte, n)
		ctr.XORKeyStream(ignore, ignore)
	}

	// Encrypt the block.
	ctr.XORKeyStream(out, in)

	return nil
}
