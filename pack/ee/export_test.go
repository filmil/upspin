// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ee

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"upspin.io/errors"
	"upspin.io/upspin"
)

// Exported for testing only.
func NewKeyAndCipher() ([]byte, cipher.Block, error) {
	return newKeyAndCipher()
}

func SetblockPacker(b upspin.BlockPacker, dkey []byte, cipher cipher.Block) {
	bp := b.(*blockPacker)
	bp.dkey = dkey
	bp.cipher = cipher
}

// FlipEncapBit flips one bit of the ML-KEM ciphertext in the first wrapped
// key of an EEPQPack packdata, to simulate tampering.
func FlipEncapBit(pd *[]byte) error {
	var p packdata
	if err := p.Unmarshal(*pd, upspin.EEPQPack); err != nil {
		return err
	}
	if len(p.wrap) == 0 || len(p.wrap[0].encap) == 0 {
		return errors.Str("no ML-KEM ciphertext to tamper with")
	}
	p.wrap[0].encap[0] ^= 1
	return p.Marshal(pd, upspin.EEPQPack)
}

// WrapTranscript is the public part of one wrapped key: the ephemeral
// point of the ECDH exchange and, under EEPQPack, the ML-KEM ciphertext.
type WrapTranscript struct {
	Ephemeral []byte // uncompressed SEC 1 point
	Encap     []byte
}

// WrapTranscripts returns the transcript of every wrapped key in a packdata.
func WrapTranscripts(pd []byte, packing upspin.Packing) ([]WrapTranscript, error) {
	var p packdata
	if err := p.Unmarshal(pd, packing); err != nil {
		return nil, err
	}
	var out []WrapTranscript
	for _, w := range p.wrap {
		var t WrapTranscript
		if w.ephemeral.X != nil && w.ephemeral.X.Sign() != 0 {
			point, err := marshalPoint(w.ephemeral.Curve, w.ephemeral.X, w.ephemeral.Y)
			if err != nil {
				return nil, err
			}
			t.Ephemeral = point
		}
		t.Encap = w.encap
		out = append(out, t)
	}
	return out, nil
}

// RelabelWrap rewrites the key hash of the first wrapped key, so that a
// reader with that hash finds a wrapped key made for someone else.
func RelabelWrap(pd *[]byte, packing upspin.Packing, keyHash []byte) error {
	var p packdata
	if err := p.Unmarshal(*pd, packing); err != nil {
		return err
	}
	p.wrap[0].keyHash = keyHash
	return p.Marshal(pd, packing)
}

// Tamper flips the first or the last bit of the named field of the
// wrapped key at index wrap, or of a top level field, in a marshalled
// packdata. Field names are sig, sig2, keyHash, dkey, nonce,
// ephemeral.X, ephemeral.Y, encap and blockSum.
func Tamper(pd *[]byte, packing upspin.Packing, field string, last bool, wrap int) error {
	var p packdata
	if err := p.Unmarshal(*pd, packing); err != nil {
		return err
	}
	if wrap < 0 || wrap >= len(p.wrap) {
		return errors.Errorf("no wrapped key %d", wrap)
	}
	flip := func(b []byte) {
		if len(b) == 0 {
			return
		}
		if last {
			b[len(b)-1] ^= 0x01
		} else {
			b[0] ^= 0x80
		}
	}
	flipInt := func(i *big.Int) {
		b := i.Bytes()
		if len(b) == 0 {
			b = []byte{0}
		}
		flip(b)
		i.SetBytes(b)
	}
	w := &p.wrap[wrap]
	switch field {
	case "sig":
		flipInt(p.sig.R)
	case "sig2":
		flipInt(p.sig2.R)
	case "keyHash":
		flip(w.keyHash)
	case "dkey":
		flip(w.dkey)
	case "nonce":
		flip(w.nonce)
	case "ephemeral.X":
		flipInt(w.ephemeral.X)
	case "ephemeral.Y":
		flipInt(w.ephemeral.Y)
	case "encap":
		flip(w.encap)
	case "blockSum":
		flip(p.blockSum)
	default:
		return errors.Errorf("no such field %q", field)
	}
	return p.Marshal(pd, packing)
}

// ReplaceEphemeral replaces the ephemeral point of the first wrapped key
// with a fresh point on another curve.
func ReplaceEphemeral(pd *[]byte, packing upspin.Packing, curve elliptic.Curve) error {
	var p packdata
	if err := p.Unmarshal(*pd, packing); err != nil {
		return err
	}
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	p.wrap[0].ephemeral = k.PublicKey
	return p.Marshal(pd, packing)
}

// ResizeEncap replaces the ML-KEM ciphertext of the first wrapped key with
// n bytes of its own contents, padded with zeros.
func ResizeEncap(pd *[]byte, packing upspin.Packing, n int) error {
	var p packdata
	if err := p.Unmarshal(*pd, packing); err != nil {
		return err
	}
	encap := make([]byte, n)
	copy(encap, p.wrap[0].encap)
	p.wrap[0].encap = encap
	return p.Marshal(pd, packing)
}
