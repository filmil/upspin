// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package metrics serves a server's health and operational metrics on an
// internal listener, separate from the public one: Prometheus metrics at
// /metrics, health checks at /healthz, and /debug/vars and /debug/pprof/.
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
package metrics // import "upspin.io/serverutil/metrics"

import (
	"expvar"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"upspin.io/flags"
	"upspin.io/log"
	"upspin.io/rpc"
	"upspin.io/version"
)

var (
	requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "upspin_rpc_requests_total",
		Help: "RPC requests served, by service, method and result.",
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

var (
	mu     sync.Mutex
	checks = map[string]func() error{}
)

// RegisterHealthCheck adds a check that /healthz runs. A check returns nil
// when its part of the server is healthy. Registering a name again replaces
// the check.
func RegisterHealthCheck(name string, check func() error) {
	mu.Lock()
	defer mu.Unlock()
	checks[name] = check
}

// healthz runs every check and answers 200 "ok" when all pass, or 503 with
// one line for each failing check.
func healthz(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	names := make([]string, 0, len(checks))
	for n := range checks {
		names = append(names, n)
	}
	cs := make(map[string]func() error, len(checks))
	for n, c := range checks {
		cs[n] = c
	}
	mu.Unlock()
	sort.Strings(names)

	var failed []string
	for _, n := range names {
		if err := cs[n](); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", n, err))
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

// Handler returns the handler of the internal listener.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", healthz)
	mux.Handle("/debug/vars", expvar.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// start sets up the metrics that need the process running, and routes RPC
// observations here.
func start() {
	buildInfo.WithLabelValues(version.GitSHA, version.Release).Set(1)
	rpc.RequestObserver = observe
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

func serve(ln net.Listener) {
	start()
	srv := &http.Server{
		Handler:           Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Info.Printf("metrics: serving /metrics, /healthz and /debug/ on %q", ln.Addr())
	go func() {
		err := srv.Serve(ln)
		log.Error.Printf("metrics: %v", err)
	}()
}

// ServeFromFlags is Serve with the address from the -metrics_addr flag. A
// listener that cannot start is a fatal error, so that a mistyped address
// does not go unnoticed.
func ServeFromFlags() {
	if err := Serve(flags.MetricsAddr); err != nil {
		log.Fatalf("metrics: cannot listen on -metrics_addr=%q: %v", flags.MetricsAddr, err)
	}
}
