// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package metrics serves a server's health and operational metrics on an
// internal listener, separate from the public one: Prometheus metrics at
// /metrics, health checks at /healthz, and expvar at /debug/vars.
//
// The listener address comes from the -metrics_addr flag. It must not be
// reachable from outside: serve it on a loopback, Tailscale or
// cluster-internal address only. The public listener (cloud/https) refuses
// every /debug/ path.
//
// Every server gets these metrics:
//
//	upspin_rpc_requests_total{service, method, result}
//	upspin_rpc_request_duration_seconds{service, method} (not for streams)
//	upspin_build_info{git_sha, release}
//
// and the Go runtime and process metrics of the Prometheus client.
// /healthz fails until the public listener is up, and while any registered
// check fails.
package metrics // import "upspin.io/serverutil/metrics"

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"upspin.io/cloud/https"
	"upspin.io/flags"
	"upspin.io/log"
	"upspin.io/rpc"
	"upspin.io/shutdown"
	"upspin.io/version"
)

var (
	requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "upspin_rpc_requests_total",
		Help: "RPC requests served, by service, method and result. A streaming call counts when it starts.",
	}, []string{"service", "method", "result"})

	duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "upspin_rpc_request_duration_seconds",
		Help:    "Time to serve an RPC request, by service and method. Streaming calls are not included.",
		Buckets: prometheus.ExponentialBuckets(0.001, 4, 10), // 1 ms to about 4 min.
	}, []string{"service", "method"})

	buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "upspin_build_info",
		Help: "Always 1; the labels name the build (see upspin.io/version).",
	}, []string{"git_sha", "release"})
)

func init() {
	prometheus.MustRegister(requests, duration, buildInfo)
}

// observe records one RPC request; it is rpc.RequestObserver.
func observe(service, method, result string, d time.Duration) {
	requests.WithLabelValues(service, method, result).Inc()
	if result != "stream" {
		duration.WithLabelValues(service, method).Observe(d.Seconds())
	}
}

// listening is set when the public listener is up (https.OnListening).
var listening atomic.Bool

var startOnce sync.Once

// start sets up what the metrics need from the rest of the server: the
// build info, the RPC hook and the listening hook. It runs once, before any
// request is served.
func start() {
	startOnce.Do(func() {
		buildInfo.WithLabelValues(version.GitSHA, version.Release).Set(1)
		rpc.RequestObserver = observe
		https.OnListening = func() { listening.Store(true) }
	})
}

// CheckTimeout bounds how long /healthz waits for one check.
const CheckTimeout = 5 * time.Second

var (
	mu     sync.Mutex
	checks = map[string]func() error{}
)

// RegisterHealthCheck adds a check that /healthz runs. A check returns nil
// when its part of the server is healthy; one that takes longer than
// CheckTimeout counts as failed. Registering a name again replaces the
// check, and a nil check removes it.
func RegisterHealthCheck(name string, check func() error) {
	mu.Lock()
	defer mu.Unlock()
	if check == nil {
		delete(checks, name)
		return
	}
	checks[name] = check
}

// runCheck runs one check with the timeout.
func runCheck(ctx context.Context, check func() error) error {
	done := make(chan error, 1)
	go func() { done <- check() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errors.New("timed out")
	}
}

// healthz answers 200 "ok" when the public listener is up and every check
// passes, or 503 with one line for each failing check, sorted by name.
func healthz(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	cs := make(map[string]func() error, len(checks))
	for n, c := range checks {
		cs[n] = c
	}
	mu.Unlock()
	names := make([]string, 0, len(cs))
	for n := range cs {
		names = append(names, n)
	}
	sort.Strings(names)

	// The checks run at once, so that one slow check does not add to
	// the others.
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, check func() error) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), CheckTimeout)
			defer cancel()
			errs[i] = runCheck(ctx, check)
		}(i, cs[n])
	}
	wg.Wait()

	var failed []string
	if !listening.Load() {
		failed = append(failed, "listener: the public listener is not up yet")
	}
	for i, n := range names {
		if errs[i] != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", n, errs[i]))
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if len(failed) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, strings.Join(failed, "\n"))
		return
	}
	fmt.Fprintln(w, "ok")
}

// Handler returns the handler of the internal listener, for a caller that
// serves it on a listener of its own.
func Handler() http.Handler {
	start()
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", healthz)
	mux.Handle("/debug/vars", expvar.Handler())
	return mux
}

// Serve starts the internal listener on addr and returns. It does nothing
// when addr is empty. It must be called before the server starts serving
// RPC requests.
func Serve(addr string) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	serve(ln)
	return nil
}

// serve serves the internal listener on ln and returns its server.
func serve(ln net.Listener) *http.Server {
	srv := &http.Server{
		Handler:           Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	shutdown.Handle(func() { srv.Close() })
	log.Info.Printf("metrics: serving /metrics, /healthz and /debug/vars on %q", ln.Addr())
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Error.Printf("metrics: %v", err)
		}
	}()
	return srv
}

// ServeFromFlags is Serve with the address from the -metrics_addr flag. A
// listener that cannot start is a fatal error, so that a mistyped address
// does not go unnoticed. Servers call it right after parsing their flags.
func ServeFromFlags() {
	if err := Serve(flags.MetricsAddr); err != nil {
		log.Fatalf("metrics: cannot listen on -metrics_addr=%q: %v", flags.MetricsAddr, err)
	}
}
