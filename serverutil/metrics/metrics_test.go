// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"upspin.io/cloud/https"
	"upspin.io/rpc"
)

func get(t *testing.T, base, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// listen serves the internal listener on a loopback port for one test and
// restores the package state afterwards.
func listen(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(ln)
	mu.Lock()
	saved := make(map[string]func() error, len(checks))
	for n, c := range checks {
		saved[n] = c
	}
	mu.Unlock()
	t.Cleanup(func() {
		srv.Close()
		mu.Lock()
		checks = saved
		mu.Unlock()
		listening.Store(false)
	})
	return "http://" + ln.Addr().String()
}

func TestMetrics(t *testing.T) {
	base := listen(t)
	if rpc.RequestObserver == nil {
		t.Fatal("serve did not set rpc.RequestObserver")
	}
	// A service name of its own, so that the counts hold however often
	// the test runs (go test -count).
	svc := fmt.Sprintf("Test%d", time.Now().UnixNano())
	rpc.RequestObserver(svc, "Lookup", "ok", 3*time.Millisecond)
	rpc.RequestObserver(svc, "Lookup", "permission", time.Millisecond)
	rpc.RequestObserver(svc, "Watch", "stream", 0)

	code, body := get(t, base, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics: status %d", code)
	}
	for _, want := range []string{
		`upspin_rpc_requests_total{method="Lookup",result="ok",service="` + svc + `"} 1`,
		`upspin_rpc_requests_total{method="Lookup",result="permission",service="` + svc + `"} 1`,
		`upspin_rpc_requests_total{method="Watch",result="stream",service="` + svc + `"} 1`,
		`upspin_rpc_request_duration_seconds_count{method="Lookup",service="` + svc + `"} 2`,
		`upspin_build_info{`,
		`go_goroutines `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics does not contain %q", want)
		}
	}
	if strings.Contains(body, `upspin_rpc_request_duration_seconds_count{method="Watch",service="`+svc+`"}`) {
		t.Error("/metrics has a duration for a streaming call")
	}
	if code, _ := get(t, base, "/debug/vars"); code != http.StatusOK {
		t.Errorf("/debug/vars: status %d, want 200", code)
	}
	if code, _ := get(t, base, "/debug/pprof/"); code != http.StatusNotFound {
		t.Errorf("/debug/pprof/: status %d, want 404 (not served)", code)
	}
}

func TestHealthz(t *testing.T) {
	base := listen(t)

	// Not ready until the public listener is up.
	code, body := get(t, base, "/healthz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "listener:") {
		t.Errorf("/healthz before the listener = %d %q, want 503 naming the listener", code, body)
	}
	if https.OnListening == nil {
		t.Fatal("serve did not set https.OnListening")
	}
	https.OnListening()
	if code, body := get(t, base, "/healthz"); code != http.StatusOK || strings.TrimSpace(body) != "ok" {
		t.Errorf("/healthz when ready = %d %q, want 200 ok", code, body)
	}

	RegisterHealthCheck("good", func() error { return nil })
	RegisterHealthCheck("writers", func() error { return errors.New("Group/Writers not loaded") })
	RegisterHealthCheck("backend", func() error { return errors.New("storage down") })
	code, body = get(t, base, "/healthz")
	want := "backend: storage down\nwriters: Group/Writers not loaded\n"
	if code != http.StatusServiceUnavailable || body != want {
		t.Errorf("/healthz with failing checks = %d %q, want 503 %q", code, body, want)
	}

	RegisterHealthCheck("writers", nil)
	RegisterHealthCheck("backend", nil)
	if code, _ := get(t, base, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz after removing the failing checks = %d, want 200", code)
	}
}

func TestHealthzTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for CheckTimeout")
	}
	base := listen(t)
	https.OnListening()
	block := make(chan struct{})
	defer close(block)
	RegisterHealthCheck("slow", func() error { <-block; return nil })
	start := time.Now()
	code, body := get(t, base, "/healthz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "slow: timed out") {
		t.Errorf("/healthz with a hung check = %d %q", code, body)
	}
	if d := time.Since(start); d > CheckTimeout+3*time.Second {
		t.Errorf("/healthz took %v with a hung check", d)
	}
}

func TestServe(t *testing.T) {
	if err := Serve(""); err != nil {
		t.Errorf("Serve(\"\") = %v, want nil", err)
	}
	if err := Serve("not an address"); err == nil {
		t.Error("Serve with a bad address: expected an error")
	}
	// A free loopback port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := Serve(addr); err != nil {
		t.Fatalf("Serve(%q) = %v", addr, err)
	}
	if code, _ := get(t, "http://"+addr, "/metrics"); code != http.StatusOK {
		t.Errorf("/metrics on Serve's listener: status %d", code)
	}
}
