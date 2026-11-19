// SPDX-License-Identifier: Apache-2.0

package main // import "upspin.io/cmd/upspinfs"

import (
	"os"
	"syscall"
)

// Flags of fallocate(2), from linux/falloc.h.
const (
	fallocKeepSize  = 0x01
	fallocPunchHole = 0x02
)

// punchHole frees the space of [off, off+n) in f without changing its size.
func punchHole(f *os.File, off, n int64) error {
	if n <= 0 {
		return nil
	}
	return syscall.Fallocate(int(f.Fd()), fallocPunchHole|fallocKeepSize, off, n)
}
