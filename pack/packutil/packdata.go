// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package packutil provides helper functions for DirEntry Packdata computation.
package packutil // import "upspin.io/pack/packutil"

import (
	"encoding/binary"

	"upspin.io/bind"
	"upspin.io/errors"
	"upspin.io/upspin"
)

// PutBytes stores the varint-encoded length of src in dst, followed by a copy of src.
// It returns the number of bytes written to dst.
func PutBytes(dst, src []byte) int {
	vlen := binary.PutVarint(dst, int64(len(src)))
	return vlen + copy(dst[vlen:], src)
}

// GetBytes copies (part of) src to dst, based on a length header.
// It returns the number of bytes consumed, including the header.
// It returns an errors.Invalid error, with dst set to empty and nothing
// consumed, if the header is malformed or names more bytes than src holds
// or dst has room for. Packdata comes from a directory server, so callers
// must treat it as untrusted and stop at the first error.
func GetBytes(dst *[]byte, src []byte) (int, error) {
	n, vlen := binary.Varint(src)
	if vlen <= 0 || n < 0 || n > int64(cap(*dst)) || n > int64(len(src)-vlen) {
		*dst = (*dst)[:0]
		return 0, errors.E(errors.Invalid, errors.Errorf("packdata: bad length %d with %d bytes left and room for %d", n, len(src), cap(*dst)))
	}
	*dst = (*dst)[:n]
	k := copy(*dst, src[vlen:n+int64(vlen)])
	return k + vlen, nil
}

// GetPublicKey returns the string representation of a user's public key.
func GetPublicKey(cfg upspin.Config, user upspin.UserName) (upspin.PublicKey, error) {
	// Are we requesting our own public key?
	if string(user) == string(cfg.UserName()) {
		return cfg.Factotum().PublicKey(), nil
	}
	keyServer, err := bind.KeyServer(cfg, cfg.KeyEndpoint())
	if err != nil {
		return "", err
	}
	u, err := keyServer.Lookup(user)
	if err != nil {
		return "", err
	}
	if len(u.PublicKey) == 0 {
		return "", errors.E(user, errors.NotExist, "no known keys for user")
	}
	return u.PublicKey, nil
}
