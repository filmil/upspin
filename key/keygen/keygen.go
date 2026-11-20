// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package keygen provides functions for generating Upspin key pairs and
// writing them to files.
package keygen // import "upspin.io/key/keygen"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/key/proquint"
	"upspin.io/pack/ee"
	"upspin.io/upspin"
)

// Format is how SaveKeysAs writes the key files public.upspinkey,
// secret.upspinkey and secret2.upspinkey.
type Format string

const (
	// JSON writes each file as a JSON object with named fields, as
	// described in upspin.io/factotum (keyfile.go). Releases since
	// v46.1.0 read it.
	JSON Format = "json"
	// Lines writes the line format, which every release reads.
	Lines Format = "lines"
)

// ParseFormat returns the Format named by s: "json" or "lines".
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case JSON, Lines:
		return f, nil
	}
	return "", errors.E(errors.Invalid, errors.Errorf("unknown key file format %q; use %q or %q", s, JSON, Lines))
}

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

// writeKeys saves both the public and private keys to their respective files,
// in the given format. If secretStr is non-empty it is kept with the private
// key: as a comment in the line format, or as "secret_seed" in JSON.
// writeKeys will overwrite any existing keys.
func writeKeys(format Format, where, publicKey, privateKey, secretStr string) error {
	if format == JSON {
		pub, priv, err := jsonKeys(publicKey, privateKey, secretStr)
		if err != nil {
			return err
		}
		publicKey, privateKey = pub, priv
	} else if secretStr != "" {
		privateKey = strings.TrimSpace(privateKey) + " # " + secretStr + "\n"
	}
	err := writeKeyFile(filepath.Join(where, "secret.upspinkey"), privateKey)
	if err != nil {
		return err
	}
	return writeKeyFile(filepath.Join(where, "public.upspinkey"), publicKey)
}

// jsonKeys returns the JSON files for a key pair given in the line format.
func jsonKeys(publicKey, privateKey, secretStr string) (pub, priv string, err error) {
	pf, err := factotum.PublicKeyFileFromKey(upspin.PublicKey(publicKey))
	if err != nil {
		return "", "", err
	}
	sf, err := factotum.PrivateKeyFileFromLines(pf.Type, privateKey)
	if err != nil {
		return "", "", err
	}
	if secretStr != "" {
		sf.SecretSeed = secretStr
	}
	pb, err := factotum.MarshalKeyFile(pf)
	if err != nil {
		return "", "", err
	}
	sb, err := factotum.MarshalKeyFile(sf)
	if err != nil {
		return "", "", err
	}
	return string(pb), string(sb), nil
}

// SaveKeys is SaveKeysAs in the line format, which every release reads.
func SaveKeys(where string, rotate bool, newPublic, newPrivate, secretStr string) error {
	return SaveKeysAs(Lines, where, rotate, newPublic, newPrivate, secretStr)
}

// SaveKeysAs writes the provided public and private keys, given in the line
// format, to the given directory in the given file format, rotating them if
// requested by adding the old pair to secret2.upspinkey.
// If secretStr is non-empty it is kept with the private key.
// If rotate is false and there are existing keys, SaveKeysAs returns an error.
// If rotate is true and there are no existing keys, SaveKeysAs returns an error.
//
// In the JSON format, a rotation writes the whole archive as JSON, converting
// one written in the line format; in the line format, it converts one written
// as JSON to lines. Either way it first checks that the old keys and the
// archive load together, and replaces the archive through a temporary file.
func SaveKeysAs(format Format, where string, rotate bool, newPublic, newPrivate, secretStr string) error {
	if _, err := ParseFormat(string(format)); err != nil {
		return err
	}
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
		return writeKeys(format, where, newPublic, newPrivate, secretStr)
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
	// The existing files may be written as JSON. The archive is written
	// in the line format, so convert them first.
	pub, err := factotum.PublicKeyFromFile(public)
	if err != nil {
		return err // Halt. Existing files are corrupted and need manual attention.
	}
	public = []byte(pub)
	if private, err = factotum.PrivateKeyFromFile(private); err != nil {
		return err // Halt. Existing files are corrupted and need manual attention.
	}
	if string(public) == newPublic && string(private) == newPrivate {
		return nil // No need to save duplicates.
	}

	var modtime string
	info, err := os.Stat(privateFile)
	if err != nil {
		modtime = ""
	} else {
		modtime = info.ModTime().UTC().Format(" 2006-01-02 15:04:05Z")
	}

	if format == JSON {
		if err := archiveJSON(archiveFile, public, private, strings.TrimSpace(modtime)); err != nil {
			return err
		}
		return writeKeys(format, where, newPublic, newPrivate, secretStr)
	}

	// An archive written as JSON cannot take a key pair appended in the
	// line format, so rewrite it in the line format first. Check that the
	// old keys and the archive load before anything is written.
	if err := archiveToLines(archiveFile, public, private); err != nil {
		return err
	}

	// Write old key pair to archive file.
	archive, err := os.OpenFile(archiveFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err // We don't have permission to archive old keys?
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
	return writeKeys(format, where, newPublic, newPrivate, secretStr)
}

// archiveJSON adds the old key pair, public and private in the line format,
// to the key archive and writes the whole archive as JSON. It checks first
// that the old pair and the archive load together.
func archiveJSON(archiveFile string, public, private []byte, date string) error {
	data, err := os.ReadFile(archiveFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines, err := factotum.ArchiveFromFile(data)
	if err != nil {
		return err // Halt. The archive needs manual attention.
	}
	if _, err := factotum.NewFromKeys(public, private, lines); err != nil {
		return errors.Errorf("existing keys in %s do not load: %v", filepath.Dir(archiveFile), err)
	}
	f, err := factotum.ArchiveFileFromLines(lines)
	if err != nil {
		return err // Halt. The archive needs manual attention.
	}
	pub, err := factotum.PublicKeyFileFromKey(upspin.PublicKey(public))
	if err != nil {
		return err
	}
	priv, err := factotum.PrivateKeyFileFromLines(pub.Type, string(private))
	if err != nil {
		return err
	}
	f.Keys = append(f.Keys, factotum.ArchivedKeyPair{Date: date, Public: pub, Private: priv})
	out, err := factotum.MarshalKeyFile(f)
	if err != nil {
		return err
	}
	// The new archive must load with the old pair, and hold every key the
	// old one held plus that pair.
	check, err := factotum.ArchiveFromFile(out)
	if err != nil {
		return err
	}
	if _, err := factotum.NewFromKeys(public, private, check); err != nil {
		return errors.Errorf("the rewritten key archive does not load: %v", err)
	}
	return replaceFile(archiveFile, out)
}

// replaceFile writes data to name through a temporary file and a rename, so
// that an interrupted write leaves the old file in place.
func replaceFile(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // No effect after a successful rename.
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}

// archiveToLines checks that the old key pair, public and private in the
// line format, and the key archive load together, and rewrites the
// archive in the line format if it is written as JSON. A missing archive,
// or one in the line format, is left as it is. The rewrite goes through a
// temporary file and a rename, so that an interrupted write leaves the old
// archive in place.
func archiveToLines(archiveFile string, public, private []byte) error {
	data, err := os.ReadFile(archiveFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines, err := factotum.ArchiveFromFile(data)
	if err != nil {
		return err // Halt. The archive needs manual attention.
	}
	if _, err := factotum.NewFromKeys(public, private, lines); err != nil {
		return errors.Errorf("existing keys in %s do not load: %v", filepath.Dir(archiveFile), err)
	}
	if bytes.Equal(lines, data) {
		return nil
	}
	return replaceFile(archiveFile, lines)
}
