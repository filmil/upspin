// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package main // import "upspin.io/cmd/upspinfs"

import "os"

// punchHole does nothing on systems without fallocate(2). The old records
// then keep their space until the file is closed.
func punchHole(f *os.File, off, n int64) error {
	return nil
}
