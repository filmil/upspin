// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

// This file holds the metrics of particular servers, which the hooks in
// cloud/storage, dir/server/serverlog and serverutil/perm report:
//
//	upspin_storage_requests_total{backend, op, result}
//	upspin_storage_request_duration_seconds{backend, op}
//	upspin_storage_bytes_total{backend, op}
//	upspin_dir_root_backups_total{result}
//	upspin_dir_root_backup_last_success_timestamp_seconds
//	upspin_dir_root_restores_total{result}
//	upspin_writers{group} (-1: the group file is missing, every user may write)
//
// and the health check "writers", which fails while any Writers group file
// is missing.

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"upspin.io/cloud/storage"
	"upspin.io/dir/server/serverlog"
	"upspin.io/rpc"
	"upspin.io/serverutil/perm"
	"upspin.io/upspin"
)

var (
	storageRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "upspin_storage_requests_total",
		Help: "Calls to a storage backend, by backend, operation and result.",
	}, []string{"backend", "op", "result"})

	storageDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "upspin_storage_request_duration_seconds",
		Help:    "Time of a call to a storage backend, by backend and operation.",
		Buckets: prometheus.ExponentialBuckets(0.001, 4, 10),
	}, []string{"backend", "op"})

	storageBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "upspin_storage_bytes_total",
		Help: "Bytes put to and downloaded from a storage backend, by backend and operation.",
	}, []string{"backend", "op"})

	rootBackups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "upspin_dir_root_backups_total",
		Help: "Backups of users' roots to the storage backend, by result.",
	}, []string{"result"})

	// A vector without labels, so that the series exists only after the
	// first successful backup: a 0 would look like a very old backup.
	rootBackupLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "upspin_dir_root_backup_last_success_timestamp_seconds",
		Help: "Unix time of the last successful backup of a root to the storage backend. Absent before the first one.",
	}, nil)

	rootRestores = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "upspin_dir_root_restores_total",
		Help: "Roots found missing locally and handled from their backup: restored, skipped (not the user's root) or failed.",
	}, []string{"result"})

	writersGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "upspin_writers",
		Help: "Number of users in a Writers group, or -1 when its file is missing and every user may write.",
	}, []string{"group"})
)

func init() {
	prometheus.MustRegister(storageRequests, storageDuration, storageBytes,
		rootBackups, rootBackupLastSuccess, rootRestores, writersGauge)
}

// startServers sets the server hooks; start calls it once.
func startServers() {
	storage.Instrument = instrument
	serverlog.RootSaveObserver = observeRootSave
	serverlog.RootRestoreObserver = func(result string) { rootRestores.WithLabelValues(result).Inc() }
	perm.WritersObserver = observeWriters
	RegisterHealthCheck("writers", checkWriters)
}

func observeRootSave(err error) {
	if err != nil {
		rootBackups.WithLabelValues(rpc.Result(err)).Inc()
		return
	}
	rootBackups.WithLabelValues("ok").Inc()
	rootBackupLastSuccess.WithLabelValues().SetToCurrentTime()
}

var (
	writersMu sync.Mutex
	writers   = map[upspin.PathName]int{}
)

func observeWriters(group upspin.PathName, n int) {
	writersMu.Lock()
	defer writersMu.Unlock()
	writers[group] = n
	writersGauge.WithLabelValues(string(group)).Set(float64(n))
}

// checkWriters fails while any Writers group file this process watches is
// missing, since then every user may write to the store.
func checkWriters() error {
	writersMu.Lock()
	defer writersMu.Unlock()
	var missing []string
	for g, n := range writers {
		if n < 0 {
			missing = append(missing, string(g))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("%s missing: every user may write", strings.Join(missing, ", "))
}

// measured is a Storage that reports its calls.
type measured struct {
	backend string
	s       storage.Storage
}

// measuredLister is a measured Storage that keeps the Lister interface.
type measuredLister struct {
	*measured
	l storage.Lister
}

// instrument is storage.Instrument.
func instrument(backend string, s storage.Storage) storage.Storage {
	m := &measured{backend: backend, s: s}
	if l, ok := s.(storage.Lister); ok {
		return &measuredLister{measured: m, l: l}
	}
	return m
}

func (m *measured) observe(op string, start time.Time, err error) {
	storageRequests.WithLabelValues(m.backend, op, rpc.Result(err)).Inc()
	storageDuration.WithLabelValues(m.backend, op).Observe(time.Since(start).Seconds())
}

func (m *measured) LinkBase() (string, error) {
	start := time.Now()
	base, err := m.s.LinkBase()
	m.observe("link_base", start, err)
	return base, err
}

func (m *measured) Download(ref string) ([]byte, error) {
	start := time.Now()
	b, err := m.s.Download(ref)
	m.observe("download", start, err)
	if err == nil {
		storageBytes.WithLabelValues(m.backend, "download").Add(float64(len(b)))
	}
	return b, err
}

func (m *measured) Put(ref string, contents []byte) error {
	start := time.Now()
	err := m.s.Put(ref, contents)
	m.observe("put", start, err)
	if err == nil {
		storageBytes.WithLabelValues(m.backend, "put").Add(float64(len(contents)))
	}
	return err
}

func (m *measured) Delete(ref string) error {
	start := time.Now()
	err := m.s.Delete(ref)
	m.observe("delete", start, err)
	return err
}

func (m *measuredLister) List(token string) ([]upspin.ListRefsItem, string, error) {
	start := time.Now()
	refs, next, err := m.l.List(token)
	m.observe("list", start, err)
	return refs, next, err
}
