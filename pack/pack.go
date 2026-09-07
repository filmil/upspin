// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pack provides the registry for implementations of Packing algorithms.
package pack // import "upspin.io/pack"

import (
	"fmt"
	"sync"

	"upspin.io/errors"
	"upspin.io/upspin"
)

var (
	packers = make(map[upspin.Packing]upspin.Packer)
	// disabled holds packings that are registered but must not be used;
	// see SetEnabled.
	disabled = make(map[upspin.Packing]bool)
	mu       sync.Mutex
)

// Register binds a Packing code to the implementation of its algorithm.
// It must be called in the init function of a Packer implementation.
// If multiple calls have the same Packing, Register will panic.
// TODO: One day, or in other languages, we may be able to bind lazily.
func Register(packer upspin.Packer) error {
	packing := packer.Packing()
	if packing == upspin.UnassignedPack {
		return errors.E(errors.Invalid, "unassigned pack cannot be registered")
	}
	mu.Lock()
	defer mu.Unlock()
	if p, present := packers[packer.Packing()]; present {
		panic(fmt.Sprintf("pack: Register(%d) already installed as %q", p.Packing(), p))
	}
	packers[packing] = packer
	return nil
}

// SetEnabled marks a packing as usable or not, for the whole process.
// This is the one place that state lives; the -eepq flag, the ee packer,
// config parsing and valid.DirEntry all consult it. A disabled packing
// stays registered and Lookup still returns it, so that every operation on
// it can fail with an error that names the flag instead of "unknown
// packing"; the packer itself, config and valid enforce the refusal. A
// packer that must be opted into, such as EEPQPack, disables itself in
// its init function. The gate is advisory: any code in the process can
// call SetEnabled, which is acceptable for an experiment.
func SetEnabled(p upspin.Packing, on bool) {
	mu.Lock()
	defer mu.Unlock()
	if on {
		delete(disabled, p)
	} else {
		disabled[p] = true
	}
}

// Enabled reports whether a packing is registered and not disabled.
func Enabled(p upspin.Packing) bool {
	mu.Lock()
	defer mu.Unlock()
	_, registered := packers[p]
	return registered && !disabled[p]
}

// Lookup returns the implementation of the specified Packing, or nil if none is registered.
// A disabled packing is returned too; see SetEnabled.
func Lookup(p upspin.Packing) upspin.Packer {
	mu.Lock()
	packer := packers[p]
	mu.Unlock() // Not worth a defer.
	return packer
}

// LookupByName returns the implementation of the specified Packing, or nil if none is registered.
// A disabled packing is returned too; see SetEnabled.
func LookupByName(name string) upspin.Packer {
	mu.Lock()
	defer mu.Unlock()
	for _, packer := range packers {
		if packer.String() == name {
			return packer
		}
	}
	return nil
}

var (
	// ErrBadPacking indicates that the packing code is invalid.
	ErrBadPacking = errors.Str("DirEntry has incorrect Packing value")
)

// CheckPacking verifies that the DirEntry matches the packing type for Pack and Packlen.
func CheckPacking(p upspin.Packer, entry *upspin.DirEntry) error {
	if entry.Packing != p.Packing() {
		return ErrBadPacking
	}
	return nil
}
