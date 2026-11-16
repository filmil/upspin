// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"upspin.io/errors"
	"upspin.io/pack"
	"upspin.io/upspin"

	_ "upspin.io/pack/ee"
	_ "upspin.io/pack/plain"
)

type expectations struct {
	username    upspin.UserName
	keyserver   upspin.Endpoint
	dirserver   upspin.Endpoint
	storeserver upspin.Endpoint
	packing     upspin.Packing
	secrets     string
	cmdflags    string
}

var secretsDir string

func init() {
	cwd, _ := os.Getwd()
	secretsDir = filepath.Join(cwd, "../key/testdata/user1")
}

func TestInitConfig(t *testing.T) {
	expect := expectations{
		username:    "p@google.com",
		keyserver:   upspin.Endpoint{Transport: upspin.InProcess, NetAddr: ""},
		dirserver:   upspin.Endpoint{Transport: upspin.Remote, NetAddr: "who.knows:1234"},
		storeserver: upspin.Endpoint{Transport: upspin.Remote, NetAddr: "who.knows:1234"},
		packing:     upspin.EEPack,
		secrets:     secretsDir,
	}
	testConfig(t, &expect, makeConfig(&expect))
}

func TestDynamicKeyServer(t *testing.T) {
	const configuration = "username: user@example.com\nsecrets: none\n"
	config, err := InitConfig(strings.NewReader(configuration))
	if err != ErrNoFactotum {
		t.Fatalf("expected ErrNoFactotum, got %v", err)
	}
	const expected = "remote,key.example.com:443"
	if config.KeyEndpoint().String() != expected {
		t.Errorf("got %v, want %v", config.KeyEndpoint().String(), expected)
	}
}

func TestDefaults(t *testing.T) {
	expect := expectations{
		username:  "noone@nowhere.org",
		keyserver: defaultKeyEndpoint,
		packing:   upspin.EEPack,
		secrets:   secretsDir,
	}
	testConfig(t, &expect, makeConfig(&expect))
}

func TestBadKey(t *testing.T) {
	// TODO(adg): with the addition of Value to the upspin.Config interface
	// it is not clear whether the "unknown" keys should trigger errors.
	// To do this we'd need to make the config package aware of all valid
	// config keys, which may or may not be desirable.
	t.Skip("not sure whether this should be the expected behavior")

	// "name=" should be "username=".
	const config = `name: p@google.com
packing: ee
keyserver: inprocess
dirserver: inprocess
storeserver: inprocess`
	_, err := InitConfig(strings.NewReader(config))
	if err == nil {
		t.Fatalf("expected error, got none")
	}
	if !strings.Contains(err.Error(), "unrecognized key") {
		t.Fatalf("expected bad key error; got %q", err)
	}
}

func TestCmdFlags(t *testing.T) {
	config := `
keyserver: key.example.com
cmdflags:
 cacheserver:
  cachedir: /tmp
  cachesize: 1000000000
 upspinfs:
  cachedir: /tmp
dirserver: remote,dir.example.com
storeserver: store.example.com:8080
secrets: ` + secretsDir + "\n"
	expect := expectations{
		username:    "noone@nowhere.org",
		packing:     upspin.EEPack,
		keyserver:   upspin.Endpoint{Transport: upspin.Remote, NetAddr: "key.example.com:443"},
		dirserver:   upspin.Endpoint{Transport: upspin.Remote, NetAddr: "dir.example.com:443"},
		storeserver: upspin.Endpoint{Transport: upspin.Remote, NetAddr: "store.example.com:8080"},
		cmdflags: `cacheserver:
  cachedir: /tmp
  cachesize: 1000000000
upspinfs:
  cachedir: /tmp`,
	}
	testConfig(t, &expect, config)
}

func TestSetFlagValues(t *testing.T) {
	// Define flags with defaults.
	flag.CommandLine = flag.NewFlagSet("hooha", flag.ContinueOnError)
	cacheSizeFlag := flag.Int64("cachesize", 5e9, "max disk `bytes` for cache")
	writethroughFlag := flag.Bool("writethrough", false, "make storage cache writethrough")

	// Expected values
	expectedSize := int64(4000000000)
	expectedWT := true

	configuration := `
secrets: ` + secretsDir + `
cmdflags:
 cacheserver:
  cachesize: ` + fmt.Sprintf("%d", expectedSize) + `
  writethrough: ` + fmt.Sprintf("%t", expectedWT) + `
`
	config, err := InitConfig(strings.NewReader(configuration))
	if err != nil {
		t.Fatalf("could not parse config %v: %v", configuration, err)
	}
	if err := SetFlagValues(config, "cacheserver"); err != nil {
		t.Fatalf("could not apply config flags %v: %v", configuration, err)
	}
	if *cacheSizeFlag != expectedSize {
		t.Fatalf("cachesize got %v, expected %v", *cacheSizeFlag, expectedSize)
	}
	if *writethroughFlag != expectedWT {
		t.Fatalf("cachesize got %v, expected %v", *cacheSizeFlag, expectedSize)
	}

	// No flags present for upspinfs, and that's fine.
	if err := SetFlagValues(config, "upspinfs"); err != nil {
		t.Fatalf("SetFlagValues should not have failed for upspinfs: %v", err)
	}

	// Add an undefined flag and expect an error from the apply.
	configuration = `
secrets: ` + secretsDir + `
cmdflags:
 cacheserver:
  cachesize: ` + fmt.Sprintf("%d", expectedSize) + `
  writethrough: ` + fmt.Sprintf("%v", expectedWT) + `
  cachedir: /tmp
`
	config, err = InitConfig(strings.NewReader(configuration))
	if err != nil {
		t.Fatalf("could not parse config %v: %v", configuration, err)
	}
	if err := SetFlagValues(config, "cacheserver"); err == nil {
		t.Fatalf("SetFlagValues should have failed %v", configuration)
	}
}

func TestNoSecrets(t *testing.T) {
	expect := expectations{
		username: "bob@google.com",
		packing:  upspin.EEPack,
		secrets:  "none",
	}
	r := strings.NewReader(makeConfig(&expect))
	cfg, err := InitConfig(r)
	if err != ErrNoFactotum {
		t.Errorf("InitConfig returned error %v, want %v", err, ErrNoFactotum)
	}
	if cfg != nil && cfg.Factotum() != nil {
		t.Errorf("InitConfig returned a non-nil Factotum")
	}
}

func TestEndpointDefaults(t *testing.T) {
	config := `
keyserver: key.example.com
dirserver: remote,dir.example.com
storeserver: store.example.com:8080
secrets: ` + secretsDir + "\n"
	expect := expectations{
		username:    "noone@nowhere.org",
		packing:     upspin.EEPack,
		keyserver:   upspin.Endpoint{Transport: upspin.Remote, NetAddr: "key.example.com:443"},
		dirserver:   upspin.Endpoint{Transport: upspin.Remote, NetAddr: "dir.example.com:443"},
		storeserver: upspin.Endpoint{Transport: upspin.Remote, NetAddr: "store.example.com:8080"},
	}
	testConfig(t, &expect, config)
}

func makeConfig(expect *expectations) string {
	var buf bytes.Buffer

	if expect.username != "" {
		fmt.Fprintf(&buf, "username: %s\n", expect.username)
	}

	var zero upspin.Endpoint
	if expect.keyserver != zero {
		fmt.Fprintf(&buf, "keyserver: %s\n", expect.keyserver)
	}
	if expect.storeserver != zero {
		fmt.Fprintf(&buf, "storeserver: %s\n", expect.storeserver)
	}
	if expect.dirserver != zero {
		fmt.Fprintf(&buf, "dirserver: %s\n", expect.dirserver)
	}

	fmt.Fprintf(&buf, "packing: %s\n", pack.Lookup(expect.packing))

	if expect.secrets != "" {
		fmt.Fprintf(&buf, "secrets: %s\n", expect.secrets)
	}

	return buf.String()
}

func testConfig(t *testing.T, expect *expectations, configuration string) {
	config, err := InitConfig(strings.NewReader(configuration))
	if err != nil {
		t.Fatalf("could not parse config %v: %v", configuration, err)
	}
	if config.UserName() != expect.username {
		t.Errorf("name: got %v expected %v", config.UserName(), expect.username)
	}
	tests := []struct {
		expected upspin.Endpoint
		got      upspin.Endpoint
	}{
		{expect.keyserver, config.KeyEndpoint()},
		{expect.dirserver, config.DirEndpoint()},
		{expect.storeserver, config.StoreEndpoint()},
	}
	for i, test := range tests {
		if test.expected != test.got {
			t.Errorf("%d: got %s expected %v", i, test.got, test.expected)
		}
	}
	if config.Packing() != expect.packing {
		t.Errorf("got %v expected %v", config.Packing(), expect.packing)
	}
	cmdflags := config.Value("cmdflags")
	if !reflect.DeepEqual(expect.cmdflags, cmdflags) {
		t.Errorf("got cmdflags\n\t%#v\nexpected\n\t%#v", cmdflags, expect.cmdflags)
	}
}

// TestExperimentalEEPQ checks the persistent opt-in for the eepq packing.
// It flips the process-wide packing switch, so it must not call
// t.Parallel and no other test in the package may run alongside it.
func TestExperimentalEEPQ(t *testing.T) {
	defer pack.SetEnabled(upspin.EEPQPack, false)

	// Without the opt-in the packing is refused.
	pack.SetEnabled(upspin.EEPQPack, false)
	_, err := InitConfig(strings.NewReader("username: u@example.com\nsecrets: none\npacking: eepq\n"))
	if !errors.Is(errors.Permission, err) {
		t.Errorf("packing eepq without opt-in: got %v, want Permission", err)
	}
	// With it, the config parses (ErrNoFactotum is the usual answer for
	// "secrets: none") and the switch is on for the process.
	_, err = InitConfig(strings.NewReader("username: u@example.com\nsecrets: none\nexperimental: eepq\npacking: eepq\n"))
	if err != ErrNoFactotum {
		t.Errorf("packing eepq with experimental: eepq: got %v, want ErrNoFactotum", err)
	}
	if !pack.Enabled(upspin.EEPQPack) {
		t.Errorf("experimental: eepq did not enable the packing")
	}
	// An unknown feature is an error.
	pack.SetEnabled(upspin.EEPQPack, false)
	_, err = InitConfig(strings.NewReader("username: u@example.com\nsecrets: none\nexperimental: eepq, warp\n"))
	if !errors.Is(errors.Invalid, err) {
		t.Errorf("unknown experimental feature: got %v, want Invalid", err)
	}
}

// TestCmdFlagsJSON checks that the config of TestCmdFlags, written as
// JSON, gives the same values, nested cmdflags included.
func TestCmdFlagsJSON(t *testing.T) {
	config := `{
  "keyserver": "key.example.com",
  "cmdflags": {
    "cacheserver": {"cachedir": "/tmp", "cachesize": 1000000000},
    "upspinfs": {"cachedir": "/tmp"}
  },
  "dirserver": "remote,dir.example.com",
  "storeserver": "store.example.com:8080",
  "secrets": "` + secretsDir + `"
}
`
	expect := expectations{
		username:    "noone@nowhere.org",
		packing:     upspin.EEPack,
		keyserver:   upspin.Endpoint{Transport: upspin.Remote, NetAddr: "key.example.com:443"},
		dirserver:   upspin.Endpoint{Transport: upspin.Remote, NetAddr: "dir.example.com:443"},
		storeserver: upspin.Endpoint{Transport: upspin.Remote, NetAddr: "store.example.com:8080"},
		cmdflags: `cacheserver:
  cachedir: /tmp
  cachesize: 1000000000
upspinfs:
  cachedir: /tmp`,
	}
	testConfig(t, &expect, config)
}

// TestJSONNumbers checks that a whole number in a JSON config keeps its
// decimal form, both as a top-level value and as a command flag, and is
// not turned into a float such as 1e+10.
func TestJSONNumbers(t *testing.T) {
	vals := map[string]string{"cachesize": ""}
	other := map[string]interface{}{}
	if err := valsFromYAML(vals, other, []byte(`{"cachesize": 10000000000, "x": {"n": 10000000000, "f": 1.5, "u": 18446744073709551615}}`)); err != nil {
		t.Fatal(err)
	}
	if got, want := vals["cachesize"], "10000000000"; got != want {
		t.Errorf("cachesize: got %q, want %q", got, want)
	}
	x, ok := other["x"].(map[string]interface{})
	if !ok {
		t.Fatalf("x: got %T, want a map", other["x"])
	}
	if got, want := x["n"], int64(10000000000); got != want {
		t.Errorf("x.n: got %#v, want %#v", got, want)
	}
	if got, want := x["f"], 1.5; got != want {
		t.Errorf("x.f: got %#v, want %#v", got, want)
	}
	if got, want := x["u"], uint64(18446744073709551615); got != want {
		t.Errorf("x.u: got %#v, want %#v", got, want)
	}
}

// TestJSONTrailingData checks that data after the JSON object is not
// ignored: such a file is not JSON, and it falls back to YAML.
func TestJSONTrailingData(t *testing.T) {
	for _, data := range []string{`{"username": "u@example.com"}}`, `{"username": "u@example.com"}] junk`} {
		if _, err := valsFromJSON([]byte(data)); err == nil {
			t.Errorf("valsFromJSON(%q): no error for trailing data", data)
		}
	}
}

// TestJSONAndYAMLAgree checks that the same config written as JSON and
// as YAML gives the same values.
func TestJSONAndYAMLAgree(t *testing.T) {
	yamlCfg := "username: u@example.com\nsecrets: none\nkeyserver: remote,key.example.com:443\npacking: plain\n"
	jsonCfg := `{"username": "u@example.com", "secrets": "none", "keyserver": "remote,key.example.com:443", "packing": "plain"}`
	parse := func(s string) (map[string]string, map[string]interface{}) {
		t.Helper()
		vals := map[string]string{"username": "", "secrets": "", "keyserver": "", "packing": ""}
		other := map[string]interface{}{}
		if err := valsFromYAML(vals, other, []byte(s)); err != nil {
			t.Fatalf("parsing %q: %v", s, err)
		}
		return vals, other
	}
	yv, yo := parse(yamlCfg)
	jv, jo := parse(jsonCfg)
	if !reflect.DeepEqual(yv, jv) || len(yo) != 0 || len(jo) != 0 {
		t.Errorf("YAML gives %v %v; JSON gives %v %v", yv, yo, jv, jo)
	}
}

// TestJSONFallbackToYAML checks that data starting with "{" that is not
// valid JSON is still read as YAML, and that data valid as neither gets
// an error naming both attempts.
func TestJSONFallbackToYAML(t *testing.T) {
	vals := map[string]string{"username": "", "secrets": ""}
	other := map[string]interface{}{}
	// A YAML flow mapping: not JSON, as the keys are not quoted.
	if err := valsFromYAML(vals, other, []byte("{username: u@example.com, secrets: none}")); err != nil {
		t.Fatalf("YAML flow mapping: %v", err)
	}
	if vals["username"] != "u@example.com" || vals["secrets"] != "none" {
		t.Errorf("YAML flow mapping: got %v", vals)
	}
	err := valsFromYAML(vals, other, []byte(`{"username": "u@example.com",`))
	if err == nil {
		t.Fatal("no error for a truncated JSON object")
	}
	if !strings.Contains(err.Error(), "as JSON") || !strings.Contains(err.Error(), "as YAML") {
		t.Errorf("error %q should name both the JSON and the YAML attempt", err)
	}
}

// TestOtherKeyJSON checks that a key the config package does not know is
// kept and readable with Value, in a JSON config as in YAML.
func TestOtherKeyJSON(t *testing.T) {
	cfg, err := InitConfig(strings.NewReader(`{"username": "u@example.com", "secrets": "` + secretsDir + `", "otherkey": "x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Value("otherkey"); got != "x" {
		t.Errorf("Value(otherkey): got %q, want %q", got, "x")
	}
}
