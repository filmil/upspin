// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packutil

import (
	"bytes"
	"testing"

	"upspin.io/errors"
)

func TestPutGetBytes(t *testing.T) {
	dst := make([]byte, 64)
	n := PutBytes(dst, []byte("hello"))
	buf := make([]byte, 8)
	m, err := GetBytes(&buf, dst[:n])
	if err != nil {
		t.Fatal(err)
	}
	if m != n || !bytes.Equal(buf, []byte("hello")) {
		t.Errorf("GetBytes(PutBytes(hello)) = %q, %d; want hello, %d", buf, m, n)
	}
}

// TestGetBytesMalformed checks that a bad length header cannot make
// GetBytes read past src or reslice dst past its capacity.
func TestGetBytesMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"length past src": {0x14, 'a', 'b'},                          // says 10 bytes, has 2
		"length past dst": append([]byte{0x40}, make([]byte, 32)...), // says 32, dst holds 8
		"negative length": {0x01, 'a'},                               // varint -1
		"unterminated":    {0x80, 0x80, 0x80},
	}
	for name, src := range cases {
		buf := make([]byte, 8)
		n, err := GetBytes(&buf, src)
		if !errors.Is(errors.Invalid, err) {
			t.Errorf("%s: got %v, want Invalid", name, err)
		}
		if len(buf) != 0 {
			t.Errorf("%s: dst has %d bytes, want 0", name, len(buf))
		}
		if n != 0 {
			t.Errorf("%s: consumed %d bytes, want 0", name, n)
		}
	}
}
