// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package factotum

// This file reads key files that are written as JSON.
//
// The key files public.upspinkey, secret.upspinkey and secret2.upspinkey
// have a line format of their own. A key file may instead hold a JSON
// object with the same fields, named. Readers try JSON first and fall
// back to the line format, so a directory may hold files of either kind.
// The functions here turn a JSON file into the line format, which the
// rest of the package parses as before; a file in the line format comes
// back unchanged.
//
// public.upspinkey:
//
//	{"type": "p256+mlkem768", "x": "1042...", "y": "2694...",
//	 "encapsulation_key": "MIIE..."}
//
// "encapsulation_key" is present only for a key type that names a KEM.
// The public key that goes over the wire, upspin.PublicKey, keeps the
// line format: only the file changes.
//
// secret.upspinkey:
//
//	{"d": "8220...", "kem_seed": "z3Jk...", "secret_seed": "..."}
//
// "kem_seed" is present only for a key type that names a KEM; the key
// type comes from public.upspinkey, so a mismatch is found when the two
// files are loaded together. "secret_seed" is optional: it records the
// proquint words that re-create the key, and becomes the "# ..." comment
// that follows the private key in the line format, so a rotation keeps it
// in the archive.
//
// secret2.upspinkey, the archive of earlier key pairs:
//
//	{"keys": [{"date": "2026-11-16 08:00:00Z",
//	           "public": {...as in public.upspinkey...},
//	           "private": {...as in secret.upspinkey...}}]}
//
// Every key value is one token of the line format: letters, digits and
// the characters "+", "/", "=" and "-". Anything else, such as "#",
// spaces or a "{", is rejected, so that the line format built from it
// reads back as the same values.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"upspin.io/errors"
	"upspin.io/upspin"
)

// PublicKeyFile is the JSON form of public.upspinkey.
type PublicKeyFile struct {
	Type             string `json:"type"`
	X                string `json:"x"`
	Y                string `json:"y"`
	EncapsulationKey string `json:"encapsulation_key,omitempty"`
}

// PrivateKeyFile is the JSON form of secret.upspinkey.
type PrivateKeyFile struct {
	D          string `json:"d"`
	KEMSeed    string `json:"kem_seed,omitempty"`
	SecretSeed string `json:"secret_seed,omitempty"`
}

// ArchivedKeyPair is one earlier key pair in the JSON form of
// secret2.upspinkey.
type ArchivedKeyPair struct {
	Date    string         `json:"date,omitempty"`
	Public  PublicKeyFile  `json:"public"`
	Private PrivateKeyFile `json:"private"`
}

// ArchiveFile is the JSON form of secret2.upspinkey.
type ArchiveFile struct {
	Keys []ArchivedKeyPair `json:"keys"`
}

// isJSON reports whether data looks like a JSON object. The line format
// never starts with "{": its first line is a key type, a decimal number
// or a "# EE" comment.
func isJSON(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("{"))
}

// decodeStrict decodes a JSON object and rejects unknown fields, so that
// a misspelled field name is an error instead of an empty value.
func decodeStrict(data []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.Str("data after the JSON object")
	}
	return nil
}

// field checks that a required field is set and is one token of the line
// format.
func field(name, value string) error {
	if value == "" {
		return errors.Errorf("missing field %q", name)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '+', r == '/', r == '=', r == '-':
		default:
			return errors.Errorf("field %q holds %q, which a key value cannot hold", name, r)
		}
	}
	return nil
}

// oneLine checks that an optional free-text field fits on one line.
func oneLine(name, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return errors.Errorf("field %q holds a line break", name)
	}
	return nil
}

// publicLines returns the line format of a public key.
func (p PublicKeyFile) publicLines() (string, error) {
	for _, f := range []struct{ name, value string }{{"type", p.Type}, {"x", p.X}, {"y", p.Y}} {
		if err := field(f.name, f.value); err != nil {
			return "", err
		}
	}
	_, kem, err := ParseKeyType(p.Type)
	if err != nil {
		return "", err
	}
	s := p.Type + "\n" + p.X + "\n" + p.Y + "\n"
	if kem == NoKEM {
		if p.EncapsulationKey != "" {
			return "", errors.Errorf("key type %q has no KEM, but field \"encapsulation_key\" is set", p.Type)
		}
		return s, nil
	}
	if err := field("encapsulation_key", p.EncapsulationKey); err != nil {
		return "", err
	}
	return s + p.EncapsulationKey + "\n", nil
}

// privateLines returns the line format of a private key. The secret seed,
// if set, follows the last line as a "# ..." comment, as keygen writes it.
// keyType is the key type of the matching public key, or "" if it is not
// known here; when it is known, the KEM seed must match it.
func (p PrivateKeyFile) privateLines(keyType string) (string, error) {
	if err := field("d", p.D); err != nil {
		return "", err
	}
	if p.KEMSeed != "" {
		if err := field("kem_seed", p.KEMSeed); err != nil {
			return "", err
		}
	}
	if err := oneLine("secret_seed", p.SecretSeed); err != nil {
		return "", err
	}
	if keyType != "" {
		_, kem, err := ParseKeyType(keyType)
		if err != nil {
			return "", err
		}
		switch {
		case kem == NoKEM && p.KEMSeed != "":
			return "", errors.Errorf("key type %q has no KEM, but field \"kem_seed\" is set", keyType)
		case kem != NoKEM && p.KEMSeed == "":
			return "", errors.Errorf("missing field \"kem_seed\" for key type %q", keyType)
		}
	}
	lines := []string{p.D}
	if p.KEMSeed != "" {
		lines = append(lines, p.KEMSeed)
	}
	if seed := strings.TrimSpace(p.SecretSeed); seed != "" {
		lines[len(lines)-1] += " # " + seed
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// PublicKeyFromFile returns the public key held in the contents of a
// public.upspinkey file, written either as JSON or in the line format.
// It tries JSON first; contents that are not a JSON object come back
// unchanged, to be parsed in the line format.
func PublicKeyFromFile(data []byte) (upspin.PublicKey, error) {
	const op errors.Op = "factotum.PublicKeyFromFile"
	if !isJSON(data) {
		return upspin.PublicKey(data), nil
	}
	var f PublicKeyFile
	if err := decodeStrict(data, &f); err != nil {
		return "", errors.E(op, errors.Invalid, errors.Errorf("parsing JSON public key file: %v", err))
	}
	s, err := f.publicLines()
	if err != nil {
		return "", errors.E(op, errors.Invalid, errors.Errorf("JSON public key file: %v", err))
	}
	return upspin.PublicKey(s), nil
}

// PrivateKeyFromFile returns the private key held in the contents of a
// secret.upspinkey file, in the line format that NewFromKeys takes.
// Like PublicKeyFromFile, it tries JSON first and returns other contents
// unchanged.
func PrivateKeyFromFile(data []byte) ([]byte, error) {
	const op errors.Op = "factotum.PrivateKeyFromFile"
	if !isJSON(data) {
		return data, nil
	}
	var f PrivateKeyFile
	if err := decodeStrict(data, &f); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("parsing JSON private key file: %v", err))
	}
	s, err := f.privateLines("")
	if err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("JSON private key file: %v", err))
	}
	return []byte(s), nil
}

// ArchiveFromFile returns the archive of earlier key pairs held in the
// contents of a secret2.upspinkey file, in the line format that
// NewFromKeys takes. Like PublicKeyFromFile, it tries JSON first and
// returns other contents unchanged.
func ArchiveFromFile(data []byte) ([]byte, error) {
	const op errors.Op = "factotum.ArchiveFromFile"
	if !isJSON(data) {
		return data, nil
	}
	var f ArchiveFile
	if err := decodeStrict(data, &f); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("parsing JSON key archive file: %v", err))
	}
	var b strings.Builder
	for i, k := range f.Keys {
		if err := oneLine("date", k.Date); err != nil {
			return nil, errors.E(op, errors.Invalid, errors.Errorf("JSON key archive file: key %d: %v", i, err))
		}
		pub, err := k.Public.publicLines()
		if err != nil {
			return nil, errors.E(op, errors.Invalid, errors.Errorf("JSON key archive file: key %d: public: %v", i, err))
		}
		priv, err := k.Private.privateLines(k.Public.Type)
		if err != nil {
			return nil, errors.E(op, errors.Invalid, errors.Errorf("JSON key archive file: key %d: private: %v", i, err))
		}
		date := ""
		if k.Date != "" {
			date = " " + k.Date
		}
		fmt.Fprintf(&b, "# EE%s\n%s%s", date, pub, priv)
	}
	return []byte(b.String()), nil
}
