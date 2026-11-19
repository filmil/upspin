// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package main // import "upspin.io/cmd/upspinfs"

import (
	"time"

	"upspin.io/log"
	"upspin.io/upspin"
)

// supervise needs memfd_create and a FUSE device that a process can hand on,
// which only Linux provides here.
func supervise(cfg upspin.Config, mountpoint string, allowOther bool, hangTimeout time.Duration, args []string) int {
	log.Error.Printf("upspinfs: -supervise is supported on Linux only")
	return 2
}
