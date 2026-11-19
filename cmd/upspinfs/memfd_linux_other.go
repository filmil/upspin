// SPDX-License-Identifier: Apache-2.0

//go:build linux && !amd64 && !arm64

package main // import "upspin.io/cmd/upspinfs"

// sysMemfdCreate is unknown here; memFile then fails, and the supervisor
// runs without a journal.
const (
	sysMemfdCreate = 0
	memfdKnown     = false
)
