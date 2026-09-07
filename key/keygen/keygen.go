// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package keygen provides functions for generating Upspin key pairs and
// writing them to files.
package keygen // import "upspin.io/key/keygen"

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/key/proquint"
	"upspin.io/pack/ee"
)

// secret represents the secret seed for a key.
// It is the byte representation of a proquint string: 16 bytes (128 bits)
// for a classic key type and 32 bytes (256 bits) for a post-quantum key
// type, whose ML-KEM seed FIPS 203 requires to have at least the strength
// of the KEM.
type secret []byte

const (
	classicSeedLen     = 16
	postQuantumSeedLen = 32
)

// seedLen returns the seed length in bytes for a key type.
func seedLen(keyType string) (int, error) {
	_, kem, err := factotum.ParseKeyType(keyType)
	if err != nil {
		return 0, err
	}
	if kem == factotum.NoKEM {
		return classicSeedLen, nil
	}
	return postQuantumSeedLen, nil
}

// proquint encodes the secret as groups of four proquint words, words
// separated by "-" and groups by ".": one line of 47 characters for a
// classic seed, and 95 characters for a post-quantum seed.
func (b secret) proquint() string {
	var groups []string
	for i := 0; i+8 <= len(b); i += 8 {
		var words []string
		for j := i; j < i+8; j += 2 {
			words = append(words, string(proquint.Encode(binary.BigEndian.Uint16(b[j:j+2]))))
		}
		groups = append(groups, strings.Join(words, "-"))
	}
	return strings.Join(groups, ".")
}

func secretFromProquint(secretStr string) secret {
	words := strings.FieldsFunc(secretStr, func(r rune) bool { return r == '-' || r == '.' })
	b := make(secret, 2*len(words))
	for i, w := range words {
		if len(w) != 5 {
			return nil
		}
		binary.BigEndian.PutUint16(b[2*i:2*i+2], proquint.Decode([]byte(w)))
	}
	return b
}

// Generate generates a random key pair of the given key type, one of
// factotum.KeyTypes. It returns the keys in the form written to the
// *.upspinkey files and the proquint secret seed that regenerates them.
func Generate(keyType string) (public, private, secretStr string, err error) {
	n, err := seedLen(keyType)
	if err != nil {
		return "", "", "", err
	}
	b := make(secret, n)
	ee.GenEntropy(b)
	return FromSecret(keyType, b.proquint())
}

// FromSecret generates a key pair with the given key type and secret seed.
// A classic key type needs a 128 bit seed of 8 proquint words and a
// post-quantum key type a 256 bit seed of 16 words; ValidSecretSeed
// describes the format. The same key type and seed always yield the same
// key pair.
func FromSecret(keyType, secret string) (public, private, secretStr string, err error) {
	const op errors.Op = "keygen.FromSecret"
	secretStr = secret
	if !ValidSecretSeed(secretStr) {
		err := errors.Errorf("expected secret like\n"+
			"\tlusab-babad-gutih-tugad.gutuk-bisog-mudof-sakat\n"+
			"got\n\t%q", secretStr)
		return "", "", "", errors.E(op, errors.Invalid, err)
	}
	n, err := seedLen(keyType)
	if err != nil {
		return "", "", "", errors.E(op, err)
	}
	b := secretFromProquint(secretStr)
	if len(b) != n {
		err := errors.Errorf("key type %s needs a %d bit secret seed (%d proquint words); got %d bits", keyType, 8*n, n/2, 8*len(b))
		return "", "", "", errors.E(op, errors.Invalid, err)
	}
	pub, priv, err := ee.CreateKeys(keyType, b)
	if err != nil {
		return "", "", "", err
	}
	return string(pub), priv, secretStr, nil
}

// ValidSecretSeed reports whether a seed conforms to the proquint format:
// either 8 words (a 128 bit seed for classic key types) or 16 words (a 256
// bit seed for post-quantum key types), in groups of four words joined by
// "-", with groups joined by ".".
func ValidSecretSeed(seed string) bool {
	if len(seed) != 47 && len(seed) != 95 {
		return false
	}

	// Check if the seed can be converted to a secret and back to the same seed.
	return seed == secretFromProquint(seed).proquint()
}

// writeKeyFile writes a single key to its file, removing the file
// beforehand if necessary due to permission errors.
// If the file's parent directory does not exist, writeKeyFile creates it.
func writeKeyFile(name, key string) error {
	// Make the directory if it does not exist.
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return err
	}
	// Create the file.
	const create = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	fd, err := os.OpenFile(name, create, 0400)
	if os.IsPermission(err) && os.Remove(name) == nil {
		// Create may fail if file already exists and is unwritable,
		// which is how it was created.
		fd, err = os.OpenFile(name, create, 0400)
	}
	if err != nil {
		return err
	}
	// Write the key.
	_, err = fd.WriteString(key)
	if err != nil {
		fd.Close()
		return err
	}
	return fd.Close()
}

// writeKeys saves both the public and private keys to their respective files.
// If secretStr is non-empty it is appended as a comment to the private key.
// writeKeys will overwrite any existing keys.
func writeKeys(where, publicKey, privateKey, secretStr string) error {
	if secretStr != "" {
		privateKey = strings.TrimSpace(privateKey) + " # " + secretStr + "\n"
	}
	err := writeKeyFile(filepath.Join(where, "secret.upspinkey"), privateKey)
	if err != nil {
		return err
	}
	return writeKeyFile(filepath.Join(where, "public.upspinkey"), publicKey)
}

// SaveKeys writes the provided public and private keys to the given directory,
// rotating them if requested by appending the old secret to secret2.upspinkey.
// If secretStr is non-empty it is appended as a comment to the private key.
// If rotate is false and there are existing keys, SaveKeys returns an error.
// If rotate is true and there are no existing keys, SaveKeys returns an error.
func SaveKeys(where string, rotate bool, newPublic, newPrivate, secretStr string) error {
	var (
		publicFile  = filepath.Join(where, "public.upspinkey")
		privateFile = filepath.Join(where, "secret.upspinkey")
		archiveFile = filepath.Join(where, "secret2.upspinkey")
	)

	// Read existing key pair.
	private, err := os.ReadFile(privateFile)
	if os.IsNotExist(err) {
		// There is nothing to save. Did we expect there to be?
		if rotate {
			return errors.Errorf("cannot rotate keys: no prior keys exist in %s", where)
		}
		// We didn't expect key rotation, so just write the new keys.
		return writeKeys(where, newPublic, newPrivate, secretStr)
	}
	if err != nil {
		return err
	}

	// There's an existing keypair. Did we not expect it?
	if !rotate {
		return errors.Errorf("prior keys exist in %s; rerun with rotate command to update keys", where)
	}

	public, err := os.ReadFile(publicFile)
	if err != nil {
		return err // Halt. Existing files are corrupted and need manual attention.
	}
	if string(public) == newPublic && string(private) == newPrivate {
		return nil // No need to save duplicates.
	}

	// Write old key pair to archive file.
	archive, err := os.OpenFile(archiveFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err // We don't have permission to archive old keys?
	}

	var modtime string
	info, err := os.Stat(privateFile)
	if err != nil {
		modtime = ""
	} else {
		modtime = info.ModTime().UTC().Format(" 2006-01-02 15:04:05Z")
	}
	_, err = fmt.Fprintf(archive, "# EE%s\n%s%s", modtime, public, private)
	if err != nil {
		return err
	}
	err = archive.Close()
	if err != nil {
		return err
	}

	// Write the new keys.
	return writeKeys(where, newPublic, newPrivate, secretStr)
}
