// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"upspin.io/errors"
	"upspin.io/pack/packutil"
	"upspin.io/upspin"
)

// wrappedKey encodes a key that will decrypt and verify the ciphertext.
type wrappedKey struct {
	keyHash   []byte // recipient's public key
	dkey      []byte // ciphertext symmetric decryption key
	nonce     []byte
	ephemeral ecdsa.PublicKey
	// encap is the ML-KEM ciphertext encapsulated to the recipient's
	// encapsulation key. It is present only under EEPQPack.
	encap []byte
}

// packdata is a structured representation of the DirEntry's Packdata field.
type packdata struct {
	// sig is the signature with the primary owner key.
	sig upspin.Signature
	// sig2 is the signature with the previous owner key,
	// to enable smoother key rotation.
	sig2 upspin.Signature
	// wrap is the file key, encoded with a set of reader keys.
	wrap []wrappedKey
	// blockSum is a checksum of the blocks.
	blockSum []byte
}

// Marshal stores the binary-encoded version of packdata in the given slice,
// copying byte arrays to dst in the order declared in the struct definitions
// and prefixed with lengths using binary.PutVarint.
// The packing selects the wire format: EEPack omits the encap field of each
// wrapped key, and its encoding is unchanged from before EEPQPack existed;
// EEPQPack writes encap after the ephemeral point.
// A slice will be allocated and the pointer overwritten if *dst is too short.
func (pd *packdata) Marshal(dst *[]byte, packing upspin.Packing) error {
	if n := packdataLen(len(pd.wrap), packing); len(*dst) < n {
		*dst = make([]byte, n)
	}

	n := 0

	// sig
	n += packutil.PutBytes((*dst)[n:], pd.sig.R.Bytes())
	n += packutil.PutBytes((*dst)[n:], pd.sig.S.Bytes())

	// sig2
	sig2 := pd.sig2
	if sig2.R == nil {
		zero := big.NewInt(0)
		sig2 = upspin.Signature{R: zero, S: zero}
	}
	n += packutil.PutBytes((*dst)[n:], sig2.R.Bytes())
	n += packutil.PutBytes((*dst)[n:], sig2.S.Bytes())

	// wrap
	n += binary.PutVarint((*dst)[n:], int64(len(pd.wrap)))
	for _, w := range pd.wrap {
		n += packutil.PutBytes((*dst)[n:], w.keyHash)
		n += packutil.PutBytes((*dst)[n:], w.dkey)
		n += packutil.PutBytes((*dst)[n:], w.nonce)
		if w.ephemeral.X != nil {
			n += packutil.PutBytes((*dst)[n:], w.ephemeral.X.Bytes())
		} else {
			n += packutil.PutBytes((*dst)[n:], nil)
		}
		if w.ephemeral.Y != nil {
			n += packutil.PutBytes((*dst)[n:], w.ephemeral.Y.Bytes())
		} else {
			n += packutil.PutBytes((*dst)[n:], nil)
		}
		if packing == upspin.EEPQPack {
			n += packutil.PutBytes((*dst)[n:], w.encap)
		}
	}

	// blockSum
	n += packutil.PutBytes((*dst)[n:], pd.blockSum)

	*dst = (*dst)[:n]
	return nil
}

// minWrappedKeyLen is the smallest encoding of a wrapped key: the all-users
// wrap under EEPack, with a 32 byte key hash, the 32 byte dkey in clear, an
// empty nonce and an empty ephemeral point, each with a one byte length.
// It bounds the number of wrapped keys a packdata can claim.
const minWrappedKeyLen = 1 + sha256.Size + 1 + aesKeyLen + 1 + 1 + 1

// Unmarshal parses the given packdata slice, in the wire format of the
// given packing, and stores its contents in the receiver pd.
// Packdata comes from a directory server and is treated as untrusted: every
// field must have one of the lengths Marshal writes, the wrapped key count
// is bounded by the bytes that remain, the ML-KEM ciphertext buffer is sized
// from its own header rather than the largest KEM, and no trailing bytes
// are allowed.
func (pd *packdata) Unmarshal(b []byte, packing upspin.Packing) error {
	if len(b) == 0 {
		return errors.Str("nil packdata")
	}
	n := 0
	var err error
	// next reads the next length-prefixed field into dst. On failure it
	// records the error and returns false, so callers can return err.
	next := func(dst *[]byte) bool {
		var k int
		k, err = packutil.GetBytes(dst, b[n:])
		n += k
		return err == nil
	}
	malformed := func(what string, got int) error {
		return errors.E(errors.Invalid, errors.Errorf("malformed packdata: %s of %d bytes", what, got))
	}

	// sig, sig2
	buf := make([]byte, marshalBufLen)
	pd.sig.R, pd.sig.S = big.NewInt(0), big.NewInt(0)
	pd.sig2.R, pd.sig2.S = big.NewInt(0), big.NewInt(0)
	for _, i := range []*big.Int{pd.sig.R, pd.sig.S, pd.sig2.R, pd.sig2.S} {
		if !next(&buf) {
			return err
		}
		i.SetBytes(buf)
	}

	// wrap
	nwrap64, vlen := binary.Varint(b[n:])
	if vlen <= 0 {
		return errors.E(errors.Invalid, "malformed packdata: wrapped key count")
	}
	n += vlen
	if nwrap64 < 0 || nwrap64 > int64((len(b)-n)/minWrappedKeyLen) {
		return errors.E(errors.Invalid, errors.Errorf("implausible number of wrapped keys: %d", nwrap64))
	}
	pd.wrap = make([]wrappedKey, int(nwrap64))
	for i := range pd.wrap {
		w := &pd.wrap[i]
		w.keyHash = make([]byte, sha256.Size)
		if !next(&w.keyHash) {
			return err
		}
		if len(w.keyHash) != sha256.Size {
			return malformed("key hash", len(w.keyHash))
		}
		// A reader's dkey is sealed with a GCM tag; the all-users dkey is in clear.
		w.dkey = make([]byte, aesKeyLen+gcmTagSize)
		if !next(&w.dkey) {
			return err
		}
		if len(w.dkey) != aesKeyLen && len(w.dkey) != aesKeyLen+gcmTagSize {
			return malformed("wrapped key", len(w.dkey))
		}
		w.nonce = make([]byte, gcmStandardNonceSize)
		if !next(&w.nonce) {
			return err
		}
		if len(w.nonce) != 0 && len(w.nonce) != gcmStandardNonceSize {
			return malformed("nonce", len(w.nonce))
		}
		w.ephemeral = ecdsa.PublicKey{X: big.NewInt(0), Y: big.NewInt(0)}
		if !next(&buf) {
			return err
		}
		w.ephemeral.X.SetBytes(buf)
		if !next(&buf) {
			return err
		}
		w.ephemeral.Y.SetBytes(buf)
		if w.ephemeral.Y.BitLen() > 393 {
			w.ephemeral.Curve = elliptic.P521()
		} else if w.ephemeral.Y.BitLen() > 265 {
			w.ephemeral.Curve = elliptic.P384()
		} else {
			w.ephemeral.Curve = elliptic.P256()
		}
		if packing == upspin.EEPQPack {
			// Read the ciphertext length first: it must be one of the
			// ML-KEM sizes, or zero for the all-users wrap, and the buffer
			// is allocated to exactly that size.
			l, vlen := binary.Varint(b[n:])
			if vlen <= 0 || (l != 0 && l != mlkem.CiphertextSize768 && l != mlkem.CiphertextSize1024) {
				return malformed("ML-KEM ciphertext", int(l))
			}
			w.encap = make([]byte, l)
			if !next(&w.encap) {
				return err
			}
		}
	}

	// blockSum
	pd.blockSum = make([]byte, sha256.Size)
	if !next(&pd.blockSum) {
		return err
	}
	if len(pd.blockSum) != sha256.Size {
		return errors.E(errors.Invalid, "block checksum is required")
	}
	if n != len(b) {
		return errors.E(errors.Invalid, errors.Errorf("malformed packdata: %d bytes parsed of %d", n, len(b)))
	}
	return nil
}

// encapBufLen is the largest ML-KEM ciphertext, that of ML-KEM-1024.
const encapBufLen = mlkem.CiphertextSize1024

// packdataLen returns the maximum length of a packdata slice for the given
// number of wrapped keys under the given packing.
func packdataLen(nwrap int, packing upspin.Packing) int {
	intLen := binary.MaxVarintLen64

	// nWrappedKey is the size of a single encoded wrappedKey
	nWrappedKey := intLen + sha256.Size            // keyHash
	nWrappedKey += intLen + aesKeyLen + gcmTagSize // dkey
	nWrappedKey += intLen + gcmStandardNonceSize   // nonce
	nWrappedKey += 2 * (intLen + marshalBufLen)    // ephemeral
	if packing == upspin.EEPQPack {
		nWrappedKey += intLen + encapBufLen // encap
	}

	n := 4 * (intLen + marshalBufLen) // (R,S) for (sig, sig2)
	n += intLen                       // len(wrap)
	n += nwrap * nWrappedKey
	n += intLen + sha256.Size // blockSum

	// n is commonly an overestimate since the big.Int used in p256 are
	// about half the size of big.Int used in the assumed curve p521.
	// At the time of writing:
	//   marshalBufLen=66    curve.Params().BitSize + 7) >> 3 for p521
	//   MaxVarintLen64=10
	//   sha256.Size=32
	//   aesKeyLen=32
	//   gcmTagSize=16
	//   gcmStandardNonceSize=12
	//   encapBufLen=1568
	// and therefore n = 356 + nwrap*274 for EEPack
	// and n = 356 + nwrap*1852 for EEPQPack.
	// The sizes actually written are smaller; see TestPackdataSizes.
	// On a 32-bit machine, this supports well over a million readers.
	// We would redesign to use group keys long before that.
	return n
}
