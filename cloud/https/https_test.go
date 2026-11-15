// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package https

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

const (
	testCert = "../../rpc/testdata/cert.pem"
	testKey  = "../../rpc/testdata/key.pem"
)

// handshake connects a client with the given config to a server with the
// server config made by newDefaultTLSConfig, and returns the client's view.
func handshake(t *testing.T, client *tls.Config) tls.ConnectionState {
	t.Helper()
	server, err := newDefaultTLSConfig(testCert, testKey)
	if err != nil {
		t.Fatal(err)
	}
	c, s := net.Pipe()
	defer c.Close()
	// A deadline, so that a failed handshake on one side cannot leave the
	// other blocked on the unbuffered pipe.
	deadline := time.Now().Add(10 * time.Second)
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)
	done := make(chan error, 1)
	go func() {
		err := tls.Server(s, server).Handshake()
		if err != nil {
			s.Close() // Unblock the client.
		}
		done <- err
	}()
	cc := tls.Client(c, client)
	cerr := cc.Handshake()
	if cerr != nil {
		c.Close() // Unblock the server.
	}
	serr := <-done
	s.Close()
	if serr != nil {
		t.Fatalf("server handshake: %v", serr)
	}
	if cerr != nil {
		t.Fatalf("client handshake: %v", cerr)
	}
	return cc.ConnectionState()
}

func TestKeyExchange(t *testing.T) {
	for _, tc := range []struct {
		name    string
		client  *tls.Config
		want    tls.CurveID
		version uint16 // 0 means TLS 1.3.
	}{{
		// The client offers the hybrid explicitly. The server side follows
		// Go's defaults, so GODEBUG=tlsmlkem=0 would turn it off there.
		name:   "hybrid",
		client: &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}},
		want:   tls.X25519MLKEM768,
	}, {
		name:   "classic client prefers X25519",
		client: &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
		want:   tls.X25519,
	}, {
		name:   "P-256 only",
		client: &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256}},
		want:   tls.CurveP256,
	}, {
		// The hybrid is TLS 1.3 only.
		name:    "TLS 1.2",
		client:  &tls.Config{MaxVersion: tls.VersionTLS12},
		want:    tls.X25519,
		version: tls.VersionTLS12,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			tc.client.InsecureSkipVerify = true
			cs := handshake(t, tc.client)
			if cs.CurveID != tc.want {
				t.Errorf("key exchange = %v, want %v", cs.CurveID, tc.want)
			}
			want := tc.version
			if want == 0 {
				want = tls.VersionTLS13
			}
			if cs.Version != want {
				t.Errorf("version = %x, want %x", cs.Version, want)
			}
		})
	}
}
