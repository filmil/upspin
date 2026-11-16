// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package factotum

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"upspin.io/upspin"
)

// The fixture directories that hold a valid key set in the line format.
var lineFormatDirs = []string{"ok", "ok-archived", "comment", "pq", "pq-archived"}

// publicToJSON turns a public key in the line format into its JSON file
// form.
func publicToJSON(t *testing.T, lines []string) PublicKeyFile {
	t.Helper()
	p := PublicKeyFile{Type: lines[0], X: lines[1], Y: lines[2]}
	if len(lines) > 3 {
		p.EncapsulationKey = lines[3]
	}
	return p
}

// privateToJSON turns a private key in the line format, comments
// included, into its JSON file form.
func privateToJSON(t *testing.T, lines []string) PrivateKeyFile {
	t.Helper()
	var p PrivateKeyFile
	for i, l := range lines {
		value, comment, _ := strings.Cut(l, "#")
		value = strings.TrimSpace(value)
		if c := strings.TrimSpace(comment); c != "" {
			p.SecretSeed = c
		}
		switch i {
		case 0:
			p.D = value
		case 1:
			p.KEMSeed = value
		}
	}
	return p
}

// nonEmptyLines splits s into lines and drops empty ones.
func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// archiveToJSON turns a key archive in the line format into its JSON
// file form.
func archiveToJSON(t *testing.T, data string) ArchiveFile {
	t.Helper()
	var a ArchiveFile
	lines := strings.Split(data, "\n")
	for len(lines) > 0 && strings.HasPrefix(lines[0], "# EE") {
		date := strings.TrimSpace(strings.TrimPrefix(lines[0], "# EE"))
		_, kem, err := ParseKeyType(lines[1])
		if err != nil {
			t.Fatal(err)
		}
		npub, npriv := 3, 1
		if kem != NoKEM {
			npub, npriv = 4, 2
		}
		a.Keys = append(a.Keys, ArchivedKeyPair{
			Date:    date,
			Public:  publicToJSON(t, lines[1:1+npub]),
			Private: privateToJSON(t, lines[1+npub:1+npub+npriv]),
		})
		lines = lines[1+npub+npriv:]
	}
	if len(a.Keys) == 0 {
		t.Fatalf("no key pairs in archive %q", data)
	}
	return a
}

func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

// jsonCopy writes the key files of the fixture directory dir as JSON into
// a new temporary directory and returns that directory.
func jsonCopy(t *testing.T, dir string) string {
	t.Helper()
	out := t.TempDir()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("testdata", dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	writeJSON(t, filepath.Join(out, "public.upspinkey"), publicToJSON(t, nonEmptyLines(read("public.upspinkey"))))
	writeJSON(t, filepath.Join(out, "secret.upspinkey"), privateToJSON(t, nonEmptyLines(read("secret.upspinkey"))))
	if _, err := os.Stat(filepath.Join("testdata", dir, "secret2.upspinkey")); err == nil {
		writeJSON(t, filepath.Join(out, "secret2.upspinkey"), archiveToJSON(t, read("secret2.upspinkey")))
	}
	return out
}

// keyLines returns a private key without comments and empty lines, as
// parsePrivateKey reads it. The line format may keep a "# secret seed"
// comment that the JSON form holds in a field of its own.
func keyLines(private string) string {
	var out []string
	for _, l := range strings.Split(private, "\n") {
		if l = clean(l); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// sameKeys reports how two factotums differ, or "" if they hold the same
// keys in the same roles.
func sameKeys(a, b *factotum) string {
	if a.current != b.current {
		return "current keys differ"
	}
	if a.previous != b.previous {
		return "previous keys differ"
	}
	if len(a.keys) != len(b.keys) {
		return "numbers of keys differ"
	}
	for h, ka := range a.keys {
		kb, ok := b.keys[h]
		if !ok {
			return "a key is missing"
		}
		if ka.public != kb.public || keyLines(ka.private) != keyLines(kb.private) {
			return "a key pair differs"
		}
	}
	return ""
}

// TestJSONKeyFilesMatchLineFormat checks that each fixture, written as
// JSON, loads to the same keys as the line format.
func TestJSONKeyFilesMatchLineFormat(t *testing.T) {
	for _, dir := range lineFormatDirs {
		t.Run(dir, func(t *testing.T) {
			lineF, err := NewFromDir(filepath.Join("testdata", dir))
			if err != nil {
				t.Fatalf("line format: %v", err)
			}
			jsonDir := jsonCopy(t, dir)
			jsonF, err := NewFromDir(jsonDir)
			if err != nil {
				t.Fatalf("JSON: %v", err)
			}
			if d := sameKeys(lineF.(*factotum), jsonF.(*factotum)); d != "" {
				t.Errorf("JSON and line format load differently: %s", d)
			}
			if lineF.PublicKey() != jsonF.PublicKey() {
				t.Errorf("PublicKey: JSON %q, line format %q", jsonF.PublicKey(), lineF.PublicKey())
			}
		})
	}
}

// TestMixedKeyFiles checks that a directory may hold JSON and line-format
// files together.
func TestMixedKeyFiles(t *testing.T) {
	lineF, err := NewFromDir(filepath.Join("testdata", "pq-archived"))
	if err != nil {
		t.Fatal(err)
	}
	dir := jsonCopy(t, "pq-archived")
	// Put the line-format public key back; secret and archive stay JSON.
	b, err := os.ReadFile(filepath.Join("testdata", "pq-archived", "public.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "public.upspinkey"), b, 0600); err != nil {
		t.Fatal(err)
	}
	mixedF, err := NewFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d := sameKeys(lineF.(*factotum), mixedF.(*factotum)); d != "" {
		t.Errorf("mixed files load differently: %s", d)
	}
}

// TestNewFromKeysJSON checks that NewFromKeys takes JSON contents too.
func TestNewFromKeysJSON(t *testing.T) {
	dir := jsonCopy(t, "pq")
	pub, err := os.ReadFile(filepath.Join(dir, "public.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := os.ReadFile(filepath.Join(dir, "secret.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFromKeys(pub, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	lineF, err := NewFromDir(filepath.Join("testdata", "pq"))
	if err != nil {
		t.Fatal(err)
	}
	if f.PublicKey() != lineF.PublicKey() {
		t.Errorf("PublicKey: got %q, want %q", f.PublicKey(), lineF.PublicKey())
	}
}

// TestLineFormatUnchanged checks that contents in the line format pass
// through the converters unchanged.
func TestLineFormatUnchanged(t *testing.T) {
	for _, dir := range lineFormatDirs {
		for _, name := range []string{"public.upspinkey", "secret.upspinkey", "secret2.upspinkey"} {
			b, err := os.ReadFile(filepath.Join("testdata", dir, name))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []byte
			switch name {
			case "public.upspinkey":
				var pk upspin.PublicKey
				pk, err = PublicKeyFromFile(b)
				got = []byte(pk)
			case "secret.upspinkey":
				got, err = PrivateKeyFromFile(b)
			case "secret2.upspinkey":
				got, err = ArchiveFromFile(b)
			}
			if err != nil {
				t.Fatalf("%s/%s: %v", dir, name, err)
			}
			if string(got) != string(b) {
				t.Errorf("%s/%s: line format changed by the converter", dir, name)
			}
		}
	}
}

// TestBadJSONKeyFiles checks the errors for malformed JSON key files.
func TestBadJSONKeyFiles(t *testing.T) {
	const x = "8675456885640943605688654896372274741866"
	tests := []struct {
		name, file, data, want string
	}{
		{"unknown field", "public", `{"type":"p256","x":"1","y":"2","z":"3"}`, "unknown field"},
		{"missing y", "public", `{"type":"p256","x":"1"}`, `missing field "y"`},
		{"bad type", "public", `{"type":"p999","x":"1","y":"2"}`, "p999"},
		{"KEM key without encapsulation key", "public", `{"type":"p256+mlkem768","x":"1","y":"2"}`, `missing field "encapsulation_key"`},
		{"encapsulation key on classic type", "public", `{"type":"p256","x":"1","y":"2","encapsulation_key":"QQ=="}`, "has no KEM"},
		{"line break in a field", "public", `{"type":"p256","x":"1\n2","y":"2"}`, "line break"},
		{"trailing data", "public", `{"type":"p256","x":"1","y":"2"} {}`, "after the JSON object"},
		{"not JSON", "public", `{"type":`, "parsing JSON public key file"},
		{"missing d", "private", `{"kem_seed":"QQ=="}`, `missing field "d"`},
		{"private unknown field", "private", `{"d":"` + x + `","seed":"x"}`, "unknown field"},
		{"archive bad key", "archive", `{"keys":[{"public":{"type":"p256","x":"1"},"private":{"d":"1"}}]}`, "key 0: public"},
		{"archive date line break", "archive", `{"keys":[{"date":"a\nb","public":{"type":"p256","x":"1","y":"2"},"private":{"d":"1"}}]}`, `"date" holds a line break`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			switch tc.file {
			case "public":
				_, err = PublicKeyFromFile([]byte(tc.data))
			case "private":
				_, err = PrivateKeyFromFile([]byte(tc.data))
			case "archive":
				_, err = ArchiveFromFile([]byte(tc.data))
			}
			if err == nil {
				t.Fatalf("no error for %s", tc.data)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// FuzzKeyFileJSON checks that the converters never panic, and that what
// they accept is in the line format.
func FuzzKeyFileJSON(f *testing.F) {
	f.Add([]byte(`{"type":"p256","x":"1","y":"2"}`))
	f.Add([]byte(`{"d":"1","kem_seed":"QQ=="}`))
	f.Add([]byte(`{"keys":[{"date":"d","public":{"type":"p256","x":"1","y":"2"},"private":{"d":"1"}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if !isJSON(data) {
			return
		}
		if pk, err := PublicKeyFromFile(data); err == nil && strings.HasPrefix(string(pk), "{") {
			t.Errorf("PublicKeyFromFile returned JSON: %q", pk)
		}
		if b, err := PrivateKeyFromFile(data); err == nil && strings.HasPrefix(string(b), "{") {
			t.Errorf("PrivateKeyFromFile returned JSON: %q", b)
		}
		if b, err := ArchiveFromFile(data); err == nil && strings.HasPrefix(string(b), "{") {
			t.Errorf("ArchiveFromFile returned JSON: %q", b)
		}
	})
}
