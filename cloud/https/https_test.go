// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package https

import (
	"crypto/tls"
	"net"
	"testing"
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
	defer s.Close()
	done := make(chan error, 1)
	go func() { done <- tls.Server(s, server).Handshake() }()
	cc := tls.Client(c, client)
	if err := cc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return cc.ConnectionState()
}

// TestHybridKeyExchange checks that a client that offers the post-quantum
// hybrid (Go's default since 1.24) gets it.
func TestHybridKeyExchange(t *testing.T) {
	cs := handshake(t, &tls.Config{InsecureSkipVerify: true})
	if cs.CurveID != tls.X25519MLKEM768 {
		t.Errorf("key exchange = %v, want %v", cs.CurveID, tls.X25519MLKEM768)
	}
}

// TestClassicFallback checks that a client without the hybrid still
// connects, with a classic curve.
func TestClassicFallback(t *testing.T) {
	cs := handshake(t, &tls.Config{InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	if cs.CurveID != tls.CurveP256 {
		t.Errorf("key exchange = %v, want %v", cs.CurveID, tls.CurveP256)
	}
}
