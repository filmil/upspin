// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package factotum encapsulates crypto operations on user's public/private keys.
package factotum // import "upspin.io/factotum"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/hkdf"

	"upspin.io/errors"
	"upspin.io/upspin"
)

// KEM names the key encapsulation mechanism, if any, that a key type pairs
// with its elliptic curve. It is the part of a key type name after the "+",
// so "p256+mlkem768" has curve P-256 and KEM MLKEM768.
type KEM string

const (
	// NoKEM is the KEM of a classic key type such as "p256".
	NoKEM KEM = ""
	// MLKEM768 is ML-KEM-768 (FIPS 203), NIST security category 3.
	MLKEM768 KEM = "mlkem768"
	// MLKEM1024 is ML-KEM-1024 (FIPS 203), NIST security category 5.
	MLKEM1024 KEM = "mlkem1024"
)

// CiphertextSize returns the length in bytes of a ciphertext produced by
// encapsulating to a key of this KEM, and 0 for NoKEM.
func (k KEM) CiphertextSize() int {
	switch k {
	case MLKEM768:
		return mlkem.CiphertextSize768
	case MLKEM1024:
		return mlkem.CiphertextSize1024
	}
	return 0
}

// KeyTypes lists every key type name accepted by ParseKeyType, and so by
// keygen and ParsePublicKey. The first three are classic elliptic curve
// keys. The rest add an ML-KEM key pair for post-quantum key wrapping
// under the EEPQPack packing. Each curve pairs with the ML-KEM parameter
// set of matching strength, so the name does not overstate the key:
// P-256 and P-384 with ML-KEM-768 (NIST category 3) and P-521 with
// ML-KEM-1024 (category 5).
var KeyTypes = []string{
	"p256", "p384", "p521",
	"p256+mlkem768", "p384+mlkem768", "p521+mlkem1024",
}

// Decapsulator is implemented by a Factotum that holds ML-KEM keys and can
// unwrap EEPQPack data. It is separate from upspin.Factotum so that
// implementations without post-quantum keys keep compiling; pack/ee asserts
// it and reports an error when it is missing.
type Decapsulator interface {
	// Decapsulate recovers the ML-KEM shared secret from a ciphertext that
	// was encapsulated to the user's public key with the given keyHash.
	// It is the post-quantum counterpart of Factotum.ScalarMult and needs
	// the same security review at each call site: the caller must not be
	// usable as a decryption oracle.
	Decapsulate(keyHash, ciphertext []byte) (sharedSecret []byte, err error)
}

var _ Decapsulator = factotum{}

type factotumKey struct {
	keyHash      []byte
	public       upspin.PublicKey
	private      string
	ecdsaKeyPair ecdsa.PrivateKey
	// kem is the ML-KEM decapsulation key, or nil for a classic key.
	kem crypto.Decapsulator
}

type keyHashArray [sha256.Size]byte

type factotum struct {
	current  keyHashArray
	previous keyHashArray
	keys     map[keyHashArray]factotumKey
}

var _ upspin.Factotum = factotum{}

var sig0 upspin.Signature // for returning error of correct type
var errNotOnCurve = errors.Str("a crypto attack was attempted against you; see safecurves.cr.yp.to/twist.html for details")

// KeyHash returns the hash of a key, given in string format.
func KeyHash(p upspin.PublicKey) []byte {
	keyHash := sha256.Sum256([]byte(p))
	return keyHash[:]
}

// AllUsersKeyHash is the hash of upspin.AllUsersKey.
var AllUsersKeyHash = KeyHash(upspin.AllUsersKey)

// NewFromDir returns a new Factotum providing all needed private key operations,
// loading keys from a directory containing *.upspinkey files.
// Our desired end state is that Factotum is implemented on each platform by the
// best local means of protecting private keys. Please do not break the abstraction
// by hand coding direct generation or use of private keys.
func NewFromDir(dir string) (upspin.Factotum, error) {
	const op errors.Op = "factotum.NewFromDir"

	privBytes, err := readFile(op, dir, "secret.upspinkey")
	if err != nil {
		return nil, errors.E(op, err)
	}
	privBytes = stripCR(privBytes)
	pubBytes, err := readFile(op, dir, "public.upspinkey")
	if err != nil {
		return nil, errors.E(op, err)
	}
	pubBytes = stripCR(pubBytes)

	// Read older key pairs.
	s2, err := readFile(op, dir, "secret2.upspinkey")
	if err != nil && !errors.Is(errors.NotExist, err) {
		return nil, err
	}
	s2 = stripCR(s2)

	return newFactotum(errors.Op(fmt.Sprintf("%s(%q)", op, dir)), pubBytes, privBytes, s2)
}

// NewFromKeys returns a new Factotum by providing it with the raw
// representation of an Upspin user's public, private and optionally, archived
// keys.
func NewFromKeys(public, private, archived []byte) (upspin.Factotum, error) {
	const op errors.Op = "factotum.NewFromKeys"
	return newFactotum(op, public, private, archived)
}

// newFactotum creates a new Factotum using the given keys.
func newFactotum(op errors.Op, public, private, archived []byte) (upspin.Factotum, error) {
	pfk, err := makeKey(upspin.PublicKey(public), string(private))
	if err != nil {
		return nil, errors.E(op, err)
	}
	fm := make(map[keyHashArray]factotumKey)
	var h keyHashArray
	copy(h[:], pfk.keyHash)
	fm[h] = *pfk
	f := &factotum{
		current:  h,
		previous: h,
		keys:     fm,
	}

	// Current file format is "# EE date" concatenated with old public.upspinkey
	// then old secret.upspinkey, and repeat. This should be cleaned up someday
	// when we have a better idea of what other kinds of keys we need to save.
	// For now, it is cavalier about bailing out at first little mistake.
	lines := strings.Split(string(archived), "\n")
	for {
		if len(lines) < 5 {
			break // This is not enough for a complete key pair.
		}
		if !strings.HasPrefix(lines[0], "# EE") {
			break // This is not a kind of key we recognize.
		}
		// lines[0] "# EE "     Joe's key
		// lines[1] "p256"      or "p256+mlkem768"
		// lines[2] "1042...6334" public X
		// lines[3] "2694...192"  public Y
		// lines[4] "8220...5934" private D
		// A key type with a KEM has one more public line, the
		// encapsulation key, and one more private line, the KEM seed:
		// lines[4] "MIIE...=="   public encapsulation key
		// lines[5] "8220...5934" private D
		// lines[6] "z3Jk...=="   private KEM seed
		_, kem, err := ParseKeyType(lines[1])
		if err != nil {
			return f, errors.E(op, err)
		}
		npub, npriv := 3, 1
		if kem != NoKEM {
			npub, npriv = 4, 2
		}
		if len(lines) < 1+npub+npriv {
			break // This is not enough for a complete key pair.
		}
		pub := strings.Join(lines[1:1+npub], "\n") + "\n"
		privLines := lines[1+npub : 1+npub+npriv]
		// The last private line may end in a "# secretseed" comment.
		last := privLines[len(privLines)-1]
		if suffix := strings.Index(last, " "); suffix > 0 {
			privLines[len(privLines)-1] = last[:suffix]
		}
		priv := strings.Join(privLines, "\n") + "\n"
		pfk, err := makeKey(upspin.PublicKey(pub), priv)
		if err != nil {
			return f, errors.E(op, err)
		}
		lines = lines[1+npub+npriv:]
		var h keyHashArray
		copy(h[:], pfk.keyHash)
		_, ok := f.keys[h]
		if ok { // Duplicate.
			continue
		}
		f.keys[h] = *pfk
		f.previous = h
	}
	return f, nil
}

// stripCR removes \r.
func stripCR(b []byte) []byte {
	return bytes.Replace(b, []byte("\r"), []byte(""), -1)
}

// makeKey creates a factotumKey by filling in the derived fields.
func makeKey(pub upspin.PublicKey, priv string) (*factotumKey, error) {
	ePublicKey, err := ParsePublicKey(pub)
	if err != nil {
		return nil, err
	}
	ecdsaKeyPair, kem, err := parsePrivateKey(pub, ePublicKey, priv)
	if err != nil {
		return nil, err
	}
	fk := factotumKey{
		keyHash:      KeyHash(pub),
		public:       pub,
		private:      priv,
		ecdsaKeyPair: *ecdsaKeyPair,
		kem:          kem,
	}
	return &fk, nil
}

// putInt stores an int32 as four big-endian bytes in dst.
// Using fixed length here to ease porting Factotum to primitive crypto devices.
// Arguably this should be a call to binary.BigEndian.
func putInt(dst []byte, ii int) int {
	i := uint32(ii)
	dst[0] = byte(i >> 24)
	dst[1] = byte(i >> 16)
	dst[2] = byte(i >> 8)
	dst[3] = byte(i)
	return 4
}

func buggy64(dst []byte, i uint64) int {
	// TODO(ehg) This typo got in by mistake. It should read:
	// dst[0] = byte(i >> 56)
	// dst[1] = byte(i >> 48)
	// dst[2] = byte(i >> 40)
	// dst[3] = byte(i >> 32)
	// dst[4] = byte(i >> 24)
	// dst[5] = byte(i >> 16)
	// dst[6] = byte(i >> 8)
	// dst[7] = byte(i)
	// But the fix would break all existing DirEntry signatures.
	// This function is only used in one place to sign the time
	// field, which we don't currently depend on anyway.

	dst[1] = byte(i >> 56)
	dst[0] = byte(i >> 48)
	dst[0] = byte(i >> 40)
	dst[1] = byte(i >> 32)
	dst[0] = byte(i >> 24)
	dst[1] = byte(i >> 16)
	dst[2] = byte(i >> 8)
	dst[3] = byte(i)
	return 8
}

// DirEntryHash provides the basis for signing and verifying files.
func (f factotum) DirEntryHash(n, l upspin.PathName, a upspin.Attribute, p upspin.Packing, t upspin.Time, dkey, hash []byte) upspin.DEHash {
	m := len(n) + len(l) + 1 + 1 + 8 + len(dkey) + len(hash) + 7*4
	b := make([]byte, m)
	m = 0
	m += putInt(b[m:], len(n))
	m += copy(b[m:], n)
	m += putInt(b[m:], len(l))
	m += copy(b[m:], l)
	b[m] = byte(a)
	m += 1
	b[m] = byte(p)
	m += 1
	m += buggy64(b[m:], uint64(t))
	m += putInt(b[m:], len(dkey))
	m += copy(b[m:], dkey)
	m += putInt(b[m:], len(hash))
	m += copy(b[m:], hash)
	h := sha256.Sum256(b[:m])
	return upspin.DEHash(h[:])
}

// FileSign ECDSA-signs a DEHash from DirEntryHash.
func (f factotum) FileSign(hash upspin.DEHash) (upspin.Signature, error) {
	fk := f.keys[f.current]
	r, s, err := ecdsa.Sign(rand.Reader, &fk.ecdsaKeyPair, hash)
	if err != nil {
		return sig0, err
	}
	return upspin.Signature{R: r, S: s}, nil
}

// ScalarMult is the bare private key operator, used in unwrapping packed data.
func (f factotum) ScalarMult(keyHash []byte, curve elliptic.Curve, x, y *big.Int) (sx, sy *big.Int, err error) {
	const op errors.Op = "factotum.ScalarMult"
	var h keyHashArray
	copy(h[:], keyHash)
	fk, ok := f.keys[h]
	if !ok {
		err = errors.E(op, errors.Errorf("no such key %x", keyHash))
	} else {
		if !curve.IsOnCurve(x, y) {
			err = errNotOnCurve
			return
		}
		sx, sy = curve.ScalarMult(x, y, fk.ecdsaKeyPair.D.Bytes())
	}
	return
}

// Decapsulate implements Decapsulator. The ciphertext must have been
// encapsulated to the encapsulation key of the user's key with the given
// keyHash. It returns the 32-byte shared secret. It fails with
// errors.NotExist if no key has that hash and with errors.Invalid if the
// key is classic (has no KEM) or the ciphertext has the wrong length.
// ML-KEM decapsulation of a malformed or forged ciphertext does not fail;
// it returns an unrelated secret, so callers must authenticate whatever
// they derive from the result, as pack/ee does with AES-GCM.
func (f factotum) Decapsulate(keyHash, ciphertext []byte) ([]byte, error) {
	const op errors.Op = "factotum.Decapsulate"
	var h keyHashArray
	copy(h[:], keyHash)
	fk, ok := f.keys[h]
	if !ok {
		return nil, errors.E(op, errors.NotExist, errors.Errorf("no such key %x", keyHash))
	}
	if fk.kem == nil {
		return nil, errors.E(op, errors.Invalid, "key has no ML-KEM component")
	}
	secret, err := fk.kem.Decapsulate(ciphertext)
	if err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	return secret, nil
}

// Sign signs a slice of bytes with the factotum's private key.
func (f factotum) Sign(hash []byte) (upspin.Signature, error) {
	fk := f.keys[f.current]
	curveLength := (fk.ecdsaKeyPair.Curve.Params().N.BitLen() + 7) / 8
	if len(hash) > curveLength {
		return sig0, errors.E(errors.Invalid, "hash is too long to Sign")
	}
	r, s, err := ecdsa.Sign(rand.Reader, &fk.ecdsaKeyPair, hash)
	if err != nil {
		return sig0, err
	}
	return upspin.Signature{R: r, S: s}, nil
}

// Verify verifies whether the given hash's signature was signed by the private
// key corresponding to the given public key.
func Verify(hash []byte, sig upspin.Signature, key upspin.PublicKey) error {
	ecdsaPubKey, err := ParsePublicKey(key)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(ecdsaPubKey, hash, sig.R, sig.S) {
		return errors.E(errors.Invalid, "signature does not match")
	}
	return nil
}

// HKDF cryptographically mixes salt, info, and the Factotum secret and
// writes the result to out, which may be of any length but is typically
// 8 or 16 bytes. The result is unguessable without the secret, and does
// not leak the secret. For more information, see package
// golang.org/x/crypto/hkdf.
func (f factotum) HKDF(salt, info, out []byte) error {
	hash := sha256.New
	secret := []byte(f.keys[f.current].private)
	hkdf := hkdf.New(hash, secret, salt, info)
	_, err := io.ReadFull(hkdf, out)
	return err
}

// Pop derives a Factotum by switching default from the current to the previous key.
func (f factotum) Pop() upspin.Factotum {
	// Arbitrarily keep f.previous unchanged, so Pop() is idempotent.
	// We don't yet have any need to go further back in time.
	return &factotum{current: f.previous, previous: f.previous, keys: f.keys}
}

// PublicKey returns the user's latest public key.
func (f factotum) PublicKey() upspin.PublicKey {
	return f.keys[f.current].public
}

// PublicKeyFromHash returns the user's public key with matching keyHash.
func (f factotum) PublicKeyFromHash(keyHash []byte) (upspin.PublicKey, error) {
	const op errors.Op = "factotum.PublicKeyFromHash"
	if len(keyHash) == 0 {
		return "", errors.E(op, errors.Invalid, "invalid keyHash")
	}
	var h keyHashArray
	copy(h[:], keyHash)
	fk, ok := f.keys[h]
	if !ok {
		return "", errors.E(op, errors.NotExist, "no such key")
	}
	return fk.public, nil
}

// clean removes comments and starting and leading space.
func clean(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// parsePrivateKey returns the ECDSA private key and, for a key type with a
// KEM, the ML-KEM decapsulation key, given the user's public key in both
// string and ECDSA form and the string representation of the private key.
// The private key string is the decimal ECDSA scalar D on the first line,
// followed for a KEM key type by the base64 ML-KEM seed on a second line.
// Each line may end in a "# comment". Both private parts are checked
// against the public key.
func parsePrivateKey(public upspin.PublicKey, publicKey *ecdsa.PublicKey, privateKey string) (priv *ecdsa.PrivateKey, kem crypto.Decapsulator, err error) {
	const op errors.Op = "factotum.parsePrivateKey"
	fields := strings.Split(string(public), "\n")
	_, kemName, err := ParseKeyType(fields[0])
	if err != nil {
		return nil, nil, errors.E(op, errors.Invalid, err)
	}
	var lines []string
	for _, l := range strings.Split(privateKey, "\n") {
		if l = clean(l); l != "" {
			lines = append(lines, l)
		}
	}
	nlines := 1
	if kemName != NoKEM {
		nlines = 2
	}
	if len(lines) != nlines {
		return nil, nil, errors.E(op, errors.Invalid, errors.Errorf("expected %d private key lines for key type %q; got %d", nlines, fields[0], len(lines)))
	}
	var d big.Int
	err = d.UnmarshalText([]byte(lines[0]))
	if err != nil {
		return nil, nil, errors.E(op, errors.Invalid, err)
	}
	x, y := publicKey.Curve.ScalarBaseMult(d.Bytes())
	if x.Cmp(publicKey.X) != 0 || y.Cmp(publicKey.Y) != 0 {
		return nil, nil, errors.E(op, errors.Invalid, "public and private keys do not correspond")
	}
	priv = &ecdsa.PrivateKey{PublicKey: *publicKey, D: &d}
	if kemName == NoKEM {
		return priv, nil, nil
	}
	seed, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		return nil, nil, errors.E(op, errors.Invalid, errors.Errorf("ML-KEM seed: %v", err))
	}
	kem, err = NewDecapsulationKey(kemName, seed)
	if err != nil {
		return nil, nil, errors.E(op, errors.Invalid, err)
	}
	ek, err := ParseEncapsulationKey(public)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(kem.Encapsulator().Bytes(), ek.Bytes()) {
		return nil, nil, errors.E(op, errors.Invalid, "public and private ML-KEM keys do not correspond")
	}
	return priv, kem, nil
}

// ParseKeyType splits a key type name, the first line of an Upspin public
// key, into its elliptic curve and its KEM. Classic names are "p256",
// "p384" and "p521" and have KEM NoKEM. A post-quantum name appends the
// KEM of matching strength: "p256+mlkem768", "p384+mlkem768" or
// "p521+mlkem1024". It returns errors.Invalid for any other name,
// including a curve paired with a KEM of a different strength. KeyTypes
// lists the accepted names.
func ParseKeyType(keyType string) (elliptic.Curve, KEM, error) {
	const op errors.Op = "factotum.ParseKeyType"
	curveName, kemName, plus := strings.Cut(keyType, "+")
	if plus && kemName == "" {
		return nil, NoKEM, errors.E(op, errors.Invalid, errors.Errorf("empty KEM in key type: %q", keyType))
	}
	var curve elliptic.Curve
	switch curveName {
	case "p256":
		curve = elliptic.P256()
	case "p521":
		curve = elliptic.P521()
	case "p384":
		curve = elliptic.P384()
	default:
		return nil, NoKEM, errors.E(op, errors.Invalid, errors.Errorf("unknown key type: %q", keyType))
	}
	// The KEM that matches the curve's strength.
	matching := MLKEM768
	if curveName == "p521" {
		matching = MLKEM1024
	}
	switch kem := KEM(kemName); kem {
	case NoKEM, matching:
		return curve, kem, nil
	case MLKEM768, MLKEM1024:
		return nil, NoKEM, errors.E(op, errors.Invalid, errors.Errorf("key type %q mixes security levels; use %s+%s", keyType, curveName, matching))
	}
	return nil, NoKEM, errors.E(op, errors.Invalid, errors.Errorf("unknown KEM in key type: %q", keyType))
}

// NewDecapsulationKey expands a 64-byte ML-KEM seed into the decapsulation
// key for the given KEM, which must be MLKEM768 or MLKEM1024. The returned
// key's Encapsulator gives the matching public encapsulation key.
func NewDecapsulationKey(kem KEM, seed []byte) (crypto.Decapsulator, error) {
	const op errors.Op = "factotum.NewDecapsulationKey"
	var (
		dk  crypto.Decapsulator
		err error
	)
	switch kem {
	case MLKEM768:
		dk, err = mlkem.NewDecapsulationKey768(seed)
	case MLKEM1024:
		dk, err = mlkem.NewDecapsulationKey1024(seed)
	default:
		return nil, errors.E(op, errors.Invalid, errors.Errorf("key type has no KEM: %q", kem))
	}
	if err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	return dk, nil
}

// ParsePublicKey takes an Upspin representation of a public key and converts it into an ECDSA public key.
// The Upspin string representation uses \n as newline no matter what native OS it runs on.
// A post-quantum key, whose type names a KEM, has one extra line holding the
// ML-KEM encapsulation key; ParsePublicKey checks that line is present and
// returns only the ECDSA part. See ParseEncapsulationKey for the KEM part.
func ParsePublicKey(public upspin.PublicKey) (*ecdsa.PublicKey, error) {
	const op errors.Op = "factotum.ParsePublicKey"
	fields := strings.Split(string(public), "\n")
	if len(fields) < 1 {
		return nil, errors.E(op, errors.Invalid, "empty key")
	}
	curve, kem, err := ParseKeyType(fields[0])
	if err != nil {
		return nil, errors.E(op, err)
	}
	// The string is terminated by \n, hence the last field is "".
	nfields := 4
	if kem != NoKEM {
		nfields = 5
	}
	if len(fields) != nfields {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("expected keytype, %d lines and a newline; got %d %v", nfields-2, len(fields), fields))
	}
	var x, y big.Int
	_, ok := x.SetString(fields[1], 10)
	if !ok {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("%s is not a big int", fields[1]))
	}
	_, ok = y.SetString(fields[2], 10)
	if !ok {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("%s is not a big int", fields[2]))
	}
	return &ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}, nil
}

// KEMOf returns the KEM named by the key type of an Upspin public key,
// NoKEM for a classic key. It only reads the first line; see
// ParsePublicKey for full validation.
func KEMOf(public upspin.PublicKey) (KEM, error) {
	keyType, _, _ := strings.Cut(string(public), "\n")
	_, kem, err := ParseKeyType(keyType)
	return kem, err
}

// ParseEncapsulationKey returns the ML-KEM encapsulation key held on the
// fourth line of a post-quantum Upspin public key. It returns errors.Invalid
// if the key is malformed and errors.NotExist if the key type has no KEM,
// so callers can tell "classic key" apart from "broken key".
func ParseEncapsulationKey(public upspin.PublicKey) (crypto.Encapsulator, error) {
	const op errors.Op = "factotum.ParseEncapsulationKey"
	if _, err := ParsePublicKey(public); err != nil {
		return nil, err
	}
	fields := strings.Split(string(public), "\n")
	_, kem, err := ParseKeyType(fields[0])
	if err != nil {
		return nil, errors.E(op, err)
	}
	if kem == NoKEM {
		return nil, errors.E(op, errors.NotExist, errors.Errorf("key type %q has no KEM", fields[0]))
	}
	b, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("encapsulation key: %v", err))
	}
	var ek crypto.Encapsulator
	switch kem {
	case MLKEM768:
		ek, err = mlkem.NewEncapsulationKey768(b)
	case MLKEM1024:
		ek, err = mlkem.NewEncapsulationKey1024(b)
	}
	if err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	return ek, nil
}

func readFile(op errors.Op, dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil, errors.E(op, errors.NotExist, err)
	}
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	return b, nil
}
