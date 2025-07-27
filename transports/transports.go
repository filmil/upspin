// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package transports is a helper package that aggregates
// the key, store, and directory imports.
// It can be imported by Upspin programs as a convenient
// way to link with all the transport implementations.
package transports // import "upspin.io/transports"

import (
	"fmt"
	"os"
	"sync"

	"upspin.io/bind"
	"upspin.io/dir/inprocess"
	kinp "upspin.io/key/inprocess"
	"upspin.io/upspin"

	_ "upspin.io/key/transports"
	_ "upspin.io/store/transports"

	_ "upspin.io/dir/remote"
	_ "upspin.io/dir/unassigned"
)

var bindOnce sync.Once

// Init initializes the transports for the given configuration.
// It is a no-op if passed a nil config or called more than once.
//
// It should be called only by client programs, directly after parsing a
// config. This handles the case where a config specifies an inprocess
// directory server and configures that server to talk to the specified store
// server.
func Init(cfg upspin.Config) {
	if cfg == nil {
		return
	}
	if cfg.DirEndpoint().Transport == upspin.InProcess {
		bindOnce.Do(func() {
			bind.RegisterDirServer(upspin.InProcess, inprocess.New(cfg))
		})
	}
	if cfg.KeyEndpoint().Transport == upspin.Local {
		f := string(cfg.KeyEndpoint().NetAddr)
		o, err := os.Open(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "oops: %v", err)
			return
		}
		bindOnce.Do(func() {
			s, err := kinp.NewRO(o)
			if err != nil {
				fmt.Fprintf(os.Stderr, "oops2: %v", err)
				return
			}
			bind.RegisterKeyServer(upspin.Local, s)
		})
	}
}
