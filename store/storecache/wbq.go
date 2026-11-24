// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package storecache

import (
	"expvar"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"upspin.io/bind"
	"upspin.io/errors"
	"upspin.io/log"
	"upspin.io/serverutil"
	"upspin.io/upspin"
)

const (
	// Number of writer goroutines to start.
	writers = 20

	// Initial maximum number of parallel writebacks.
	initialMaxParallel = 6

	// Retry interval for endpoints that we failed to Put to.
	retryInterval = 5 * time.Minute

	// failedDirName is the directory, beside the writeback queue, where
	// blocks the store rejected permanently are kept: as in the queue,
	// failedDirName/<endpoint>/<prefix>/<reference>, each with a
	// <reference>.error file saying when and why. They are not retried.
	// To retry one, for example once a proxy's body limit is raised, move
	// the block back into the queue directory (storewritebackqueue) at the
	// same relative path, remove its .error file, and restart the
	// cacheserver: it queues every block found there at startup.
	failedDirName      = "storewritebackfailed"
	failedReasonSuffix = ".error"
)

// writebackFailed counts the blocks the store rejected permanently.
var writebackFailed = expvar.NewInt("storecache-writeback-failed")

// request represents a request to writeback a block. Each corresponds
// to a Put to the storecache.
type request struct {
	upspin.Location
	err        error       // the result of the Put() to the StoreServer.
	failed     bool        // err is permanent: the block was set aside.
	flushChans []chan bool // each flusher waits for its chan to close.
	len        int64       // inserted by writeback.
}

// flushRequest represents a requester waiting for the writeback to happen.
// flushed will be closed when it happens.
type flushRequest struct {
	upspin.Location
	flushed chan bool
}

// the values for endpointQueue.state
const (
	unknown = iota // We don't know the state.
	live           // The endpoint is alive and responding to requests.
	dead           // The endpoint is not responding or responding with errors.
)

// endpointQueue represents a queue of pending requests destined
// for an endpoint.
type endpointQueue struct {
	queue []*request // references waiting for writeback.
	state int
}

type writebackQueue struct {
	sc *storeCache

	// byEndpoint contains references to be written back. This
	// is used/modified exclusively by the scheduler goroutine.
	byEndpoint map[upspin.Endpoint]*endpointQueue

	// All queued writeback requests. Also used/modified
	// exclusively by the scheduler goroutine.
	queued   map[upspin.Location]*request
	enqueued int

	// request carries writeback requests to the scheduler.
	request chan *request

	// flushRequest carries flush requests to the scheduler.
	flushRequest chan *flushRequest

	// ready carries requests ready for writers.
	ready chan *request

	// done carries completed requests.
	done chan *request

	// retry carries queues to retry.
	retry chan *endpointQueue

	// Closing die signals all go routines to exit.
	die chan bool

	// Writers and scheduler send to terminated on exit.
	terminated chan bool

	// Queue of clients waiting for all writebacks to be flushed.
	flushChans []chan bool

	goodput *serverutil.RateCounter
	output  *serverutil.RateCounter
}

func newWritebackQueue(sc *storeCache) *writebackQueue {
	wbq := &writebackQueue{
		sc:           sc,
		byEndpoint:   make(map[upspin.Endpoint]*endpointQueue),
		queued:       make(map[upspin.Location]*request),
		request:      make(chan *request, writers),
		flushRequest: make(chan *flushRequest, writers),
		ready:        make(chan *request, writers),
		done:         make(chan *request, writers),
		retry:        make(chan *endpointQueue, writers),
		die:          make(chan bool),
		terminated:   make(chan bool),
	}
	wbq.goodput = serverutil.NewRateCounter(60, 5*time.Second)
	expvar.Publish("storecache-goodput", wbq.goodput)
	wbq.output = serverutil.NewRateCounter(60, 5*time.Second)
	expvar.Publish("storecache-output", wbq.output)

	// Start scheduler.
	go wbq.scheduler()

	// Start writers.
	for i := 0; i < writers; i++ {
		go wbq.writer(i)
	}

	return wbq
}

// enqueueWritebackFile populates the writeback queue on startup.
func (wbq *writebackQueue) enqueueWritebackFile(relPath string) {
	const op errors.Op = "store/storecache.isWritebackFile"

	if wbq == nil {
		log.Error.Printf("%s: writeback file %s but running as writethrough", op, relPath)
		return
	}
	elems := strings.Split(relPath, string(filepath.Separator))
	if len(elems) != 3 {
		log.Error.Printf("%s: odd writeback file %s", op, relPath)
		return
	}
	e, err := upspin.ParseEndpoint(elems[0])
	if err != nil {
		log.Error.Printf("%s: odd writeback file %s: %s", op, relPath, err)
		return
	}
	wbq.request <- &request{
		Location:   upspin.Location{Reference: upspin.Reference(elems[2]), Endpoint: *e},
		err:        nil,
		flushChans: nil,
	}
}

var emptyLocation upspin.Location

// scheduler puts requests into the ready queue for the writers to work on.
func (wbq *writebackQueue) scheduler() {
	const op errors.Op = "store/storecache.scheduler"
	p := newParallelism(initialMaxParallel)
	for {
		select {
		case r := <-wbq.request:
			log.Debug.Printf("%s: received %s %s", op, r.Reference, r.Endpoint)
			// Keep a map of requests so that we can handle flushes
			// and avoid Duplicates.
			if wbq.queued[r.Location] != nil {
				log.Debug.Printf("%s: %s %s already queued", op, r.Reference, r.Endpoint)
				// Already queued. Unusual but OK.
				break
			}
			wbq.queued[r.Location] = r

			// A new request
			epq := wbq.byEndpoint[r.Endpoint]
			if epq == nil {
				// New endpoints start in unknown state.
				epq = &endpointQueue{state: unknown}
				wbq.byEndpoint[r.Endpoint] = epq
			}
			epq.queue = append(epq.queue, r)
			wbq.enqueued++
			log.Debug.Printf("%s: %s %s queued", op, r.Reference, r.Endpoint)
		case r := <-wbq.done:
			// A request has been completed.
			epq := wbq.byEndpoint[r.Endpoint]
			if r.failed {
				// The store rejected the block for good, so the
				// endpoint is alive: the block is not retried, and
				// it does not hold up the rest of the queue (#139).
				p.failure(r.err)
				writebackFailed.Add(1)
				log.Error.Printf("%s: %s@%s rejected by the store, not retried; kept in %s: %s",
					op, r.Reference, r.Endpoint, failedDirName, r.err)
				epq.state = live
			} else if r.err != nil {
				epq.queue = append(epq.queue, r)
				if p.failure(r.err) {
					// The error has been dealt with. Since it was
					// probably a server timeout, count it for output.
					wbq.output.Add(r.len)
					log.Error.Printf("%s: timeout: goodput %s, output %s",
						op, wbq.goodput.String(),
						wbq.output.String())
					break
				} else {
					log.Error.Printf("%s: writeback failed: %s", op, r.err)
				}

				// Mark endpoint as dead so we don't waste time trying. Retry
				// after retryInterval.
				if epq.state != dead {
					epq.state = dead
					time.AfterFunc(retryInterval, func() { wbq.retry <- epq })
				}
				break
			} else {
				wbq.output.Add(r.len)
				wbq.goodput.Add(r.len)

				// Mark endpoint as live so we can queue more requests for it.
				epq.state = live
				p.success()
			}

			// Awaken everyone waiting for a flush of a particular block.
			for _, c := range r.flushChans {
				log.Debug.Printf("awakening block flusher")
				close(c)
			}
			delete(wbq.queued, r.Location)
			wbq.enqueued--

			// Awaken everyone waiting for a flush of all writebacks.
			if wbq.enqueued == 0 {
				for _, c := range wbq.flushChans {
					log.Debug.Printf("awakening all flusher")
					close(c)
				}
				wbq.flushChans = nil
			}

			log.Debug.Printf("%s: %s %s done", op, r.Reference, r.Endpoint)
		case epq := <-wbq.retry:
			// Set its state to unknown so we'll try a single request to feel it out.
			if epq.state == dead {
				epq.state = unknown
			}
		case fr := <-wbq.flushRequest:
			if fr.Location == emptyLocation {
				if wbq.enqueued == 0 {
					close(fr.flushed)
					break
				}
				wbq.flushChans = append(wbq.flushChans, fr.flushed)
			} else {
				r := wbq.queued[fr.Location]
				if r == nil {
					// Not in flight
					close(fr.flushed)
					break
				}
				r.flushChans = append(r.flushChans, fr.flushed)
			}
		case <-wbq.die:
			wbq.terminated <- true
			return
		}

		// Fill the ready queue.
		for {
			if !wbq.pickAndQueue(p) {
				break
			}
		}
	}
}

// pickAndQueue makes one round robin pass through the endpoint queues sending
// the first request in each queue to the ready channel.
//
// It returns false if it found nothing to do.
func (wbq *writebackQueue) pickAndQueue(p *parallelism) bool {
	sent := false
	for _, q := range wbq.byEndpoint {
		if !p.ok() {
			// Already at the max parallel requests.
			return false
		}
		if q.state == dead {
			continue
		}
		if len(q.queue) == 0 {
			continue
		}
		r := q.queue[0]
		select {
		case wbq.ready <- r:
			q.queue = q.queue[1:]
			p.add()
			if q.state == unknown {
				// Once we send a request for an unknown endpoint
				// assume it is dead until the request terminates
				// and tells us otherwise.
				q.state = dead
			}
			sent = true
		default:
			// Queue full.
			return false
		}
	}
	return sent
}

func (wbq *writebackQueue) writer(me int) {
	for {
		// Wait for something to do.
		select {
		case r := <-wbq.ready:
			r.err = nil
			r.failed = false

			// Write it back.
			r.err = wbq.writeback(r)
			wbq.done <- r
		case <-wbq.die:
			wbq.terminated <- true
			return
		}
	}
}

// writeback returns nil on success or not transient errors.
// TODO(p): still figuring out how to tell them apart.
func (wbq *writebackQueue) writeback(r *request) error {
	// Read it in.
	relPath := wbq.sc.cachePath(r.Reference, r.Endpoint)
	absPath := wbq.sc.absWritebackPath(relPath)
	data, err := wbq.sc.readFromCacheFile(absPath)
	if err != nil {
		// Nothing we can do, log it but act like we succeeded.
		log.Error.Printf("store/storecache.writer: data for %s@%s disappeared before writeback: %s", r.Reference, r.Endpoint, err)
		return nil
	}
	r.len = int64(len(data))

	// Try to write it back.
	store, err := bind.StoreServer(wbq.sc.cfg, r.Endpoint)
	if err != nil {
		return err
	}
	refdata, err := store.Put(data)
	if err != nil {
		if isPermanent(err) {
			r.failed = true
			wbq.setAside(r, relPath, absPath, err)
		}
		return err
	}
	if refdata.Reference != r.Reference {
		err := errors.Errorf("refdata mismatch expected %q got %q", r.Reference, refdata.Reference)
		return err
	}
	if err := os.Remove(absPath); err != nil {
		log.Error.Printf("store/storecache.writer: fail remove after writeback: %s", err)
	}
	log.Info.Printf("store/storecache.writer: %s@%s writeback successful", r.Reference, r.Endpoint)
	return nil
}

// requestWriteback makes a hard link to the cache file sends a request to the scheduler queue.
func (wbq *writebackQueue) requestWriteback(ref upspin.Reference, e upspin.Endpoint) error {
	// Make a link to the cache file.
	relPath := wbq.sc.cachePath(ref, e)
	cf := wbq.sc.absCachePath(relPath)
	wbf := wbq.sc.absWritebackPath(relPath)
	if err := os.Link(cf, wbf); err != nil {
		if strings.Contains(err.Error(), "exists") {
			// Someone else is already writing it back.
			return nil
		}
		os.MkdirAll(filepath.Dir(wbf), 0700)
		err := os.Link(cf, wbf)
		if err != nil {
			if strings.Contains(err.Error(), "exists") {
				// Someone else is already writing it back.
				return nil
			}
			log.Debug.Printf("%s", err)
			return err
		}
	}

	// Let the scheduler know.
	wbq.request <- &request{
		Location: upspin.Location{Reference: ref, Endpoint: e},
		len:      0,
	}
	return nil
}

// flush waits until the indicated block has been flushed.
func (wbq *writebackQueue) flush(loc upspin.Location) {
	flushed := make(chan bool)
	wbq.flushRequest <- &flushRequest{
		Location: loc,
		flushed:  flushed,
	}
	<-flushed
}

// parallelism controls the number of parallel writebacks.
// It implements a linear increase/multiplicative decrease
// model that creates a sawtooth around the maximum usable
// parallelism, that is, the max parallelism which doesn't cause
// server timeouts.
type parallelism struct {
	// inFlight is the number of writebacks being performed in parallel.
	inFlight int

	// No new requests are started unless inFlight is less than max.
	max int

	// successes is the number of error free requests since
	// the last timeout or change of max. When successes equals
	// max, we increment max.
	successes int
}

func newParallelism(max int) *parallelism {
	if max < 1 {
		max = 1
	}
	return &parallelism{max: max}
}

// failure is called when a writeback fails. It returns true if it
// has dealt with the error.
func (p *parallelism) failure(err error) bool {
	const op errors.Op = "store/storecache.failure"

	p.inFlight--

	// If we don't understand the error, let the caller handle it.
	if !isTimeout(err) {
		return false
	}

	// We have a timeout error. We assume that the error was caused by too much
	// parallelism for the line slowing down each request to less than the servers
	// can bear.

	// The sequence of successes is broken, start again. We do this after the above
	// check because failures not due to timeouts are not considered a problem in
	// parallelism.
	p.successes = 0

	// If we are above max, we're responding to a previous error, don't reduce again.
	if p.inFlight >= p.max {
		return true
	}

	// Drop max by half. max will never go below 1 if it starts above 0.
	// We assume that even at half the maximum attainable error-free
	// concurrency we will achieve maximum throughput.
	p.max = (p.max + 1) / 2
	log.Debug.Printf("%s: down %d", op, p.max)
	return true
}

// success is called whenever a writeback succeeds.
func (p *parallelism) success() {
	const op errors.Op = "store/storecache.success"

	p.inFlight--

	// inFlight below max (not enough write load) give us no information.
	if p.inFlight+1 < p.max {
		return
	}

	// Don't start counting until we terminate at p.max.
	// This lets us get down to p.max after a reduction before
	// we start increasing again.
	if p.inFlight+1 > p.max {
		return
	}

	// Count the unbroken sequence of successes after a
	// change in max.
	p.successes++

	// max can't go above the number of available writers.
	if p.max == writers {
		return
	}

	// We are trying to find a maximal p.max that will guarantee that p.max
	// writebacks can occur concurrently without a timeout error. As with TCP
	// congestion windows we approximate that with a sawtooth that increments
	// past the goal and then falls back.  We limit p.max to a large but finite
	// number, that is, the number of preallocated writers and hope that will be
	// enough. Unlimited would easily DOS the server.
	//
	// If we simultaneously start p.max writebacks and they all terminate
	// without a timeout, that would certainly prove that p.max was at or
	// lower than the maximum attainable. This heuristic approximates
	// that. In the case of a continuous queue of writebacks, it is measuring
	// exactly that. However if the offered load is fluctuating so that
	// inflight is fluctuating at and below p.max, we require only that
	// a multiple of p.max writebacks terminate while inflight is at p.max with no
	// intervening timeouts. This allows us to increase p.max even when the
	// load only sporadically increases to p.max.
	if p.successes >= 2*p.max {
		p.successes = 0
		p.max++
		log.Debug.Printf("%s: up %d", op, p.max)
	}
}

func (p *parallelism) ok() bool {
	return p.inFlight < p.max
}

func (p *parallelism) add() {
	p.inFlight++
}

// isTimeout returns true if this was the result of a server timeout.
func isTimeout(err error) bool {
	estr := err.Error()
	return strings.Contains(estr, "timeout") || strings.Contains(estr, "400")
}

// setAside moves a block the store rejected permanently out of the writeback
// queue into failedDirName, with a file saying when and why, so that it is
// neither retried nor lost. See failedDirName for how to retry it.
func (wbq *writebackQueue) setAside(r *request, relPath, absPath string, reason error) {
	const op errors.Op = "store/storecache.setAside"
	failedPath := filepath.Join(filepath.Dir(wbq.sc.wbDir), failedDirName, relPath)
	if err := os.MkdirAll(filepath.Dir(failedPath), 0700); err != nil {
		log.Error.Printf("%s: %s", op, err)
		return
	}
	if err := os.Rename(absPath, failedPath); err != nil {
		log.Error.Printf("%s: %s", op, err)
		return
	}
	text := fmt.Sprintf("time: %s\nreference: %s\nendpoint: %s\nerror: %s\n",
		time.Now().UTC().Format(time.RFC3339), r.Reference, r.Endpoint, reason)
	if err := os.WriteFile(failedPath+failedReasonSuffix, []byte(text), 0600); err != nil {
		log.Error.Printf("%s: %s", op, err)
	}
}

// httpStatus finds an HTTP status at the start of an error's text or of one
// of its parts, as the RPC client reports a response that is not 200 OK
// ("413 Request Entity Too Large: <body>").
var httpStatus = regexp.MustCompile(`(?:^|: )([1-5][0-9][0-9]) [A-Z]`)

// isPermanent reports whether a Put that failed with err will fail the same
// way however often it is retried: the store found the request invalid, or
// answered with an HTTP client error. 408 (request timeout) and 429 (too many
// requests) are retried, as are 400 (isTimeout treats it as a timeout, #144),
// server errors and network errors.
func isPermanent(err error) bool {
	if errors.Is(errors.Invalid, err) {
		return true
	}
	m := httpStatus.FindStringSubmatch(err.Error())
	if m == nil {
		return false
	}
	code, _ := strconv.Atoi(m[1])
	switch {
	case code < 400 || code > 499:
		return false
	case code == 400, code == 408, code == 429:
		return false
	}
	return true
}
