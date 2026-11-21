// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

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

func TestListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(ln)
	base := "http://" + ln.Addr().String()

	if rpc.RequestObserver == nil {
		t.Fatal("serve did not set rpc.RequestObserver")
	}
	rpc.RequestObserver("Dir", "Lookup", "ok", 3*time.Millisecond)
	rpc.RequestObserver("Dir", "Lookup", "permission", time.Millisecond)
	rpc.RequestObserver("Dir", "Watch", "stream", time.Hour)

	code, body := get(t, base, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics: status %d", code)
	}
	for _, want := range []string{
		`upspin_rpc_requests_total{method="Lookup",result="ok",service="Dir"} 1`,
		`upspin_rpc_requests_total{method="Lookup",result="permission",service="Dir"} 1`,
		`upspin_rpc_requests_total{method="Watch",result="stream",service="Dir"} 1`,
		`upspin_rpc_request_duration_seconds_count{method="Lookup",service="Dir"} 2`,
		`upspin_build_info{`,
		`go_goroutines `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics does not contain %q", want)
		}
	}
	if strings.Contains(body, `upspin_rpc_request_duration_seconds_count{method="Watch"`) {
		t.Error("/metrics has a duration for a streaming call")
	}

	if code, body := get(t, base, "/healthz"); code != http.StatusOK || strings.TrimSpace(body) != "ok" {
		t.Errorf("/healthz with no checks = %d %q, want 200 ok", code, body)
	}
	RegisterHealthCheck("good", func() error { return nil })
	RegisterHealthCheck("writers", func() error { return errors.New("Group/Writers not loaded") })
	code, body = get(t, base, "/healthz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "writers: Group/Writers not loaded") || strings.Contains(body, "good") {
		t.Errorf("/healthz with a failing check = %d %q", code, body)
	}
	RegisterHealthCheck("writers", func() error { return nil })
	if code, _ := get(t, base, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz after the check passes = %d, want 200", code)
	}

	for _, path := range []string{"/debug/vars", "/debug/pprof/"} {
		if code, _ := get(t, base, path); code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, code)
		}
	}
}

func TestServeEmptyAddr(t *testing.T) {
	if err := Serve(""); err != nil {
		t.Errorf("Serve(\"\") = %v, want nil", err)
	}
}

func TestServeBadAddr(t *testing.T) {
	if err := Serve("not an address"); err == nil {
		t.Error("Serve with a bad address: expected an error")
	}
}
