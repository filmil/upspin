// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run make_version.go

// The version package is used by the release process to add an
// informative version string to some commands.
package version

import (
	"fmt"
	"time"
)

// These are set by Bazel stamping in a --stamp build, as the release job
// makes (version/BUILD.bazel, tools/workspace_status.sh), or by an init
// function created by make_version.go in a go generate build.
var (
	BuildTime = time.Time{}
	GitSHA    = ""
	// Release is the release tag, such as v46.2.0, or empty.
	Release = ""
	// buildTime is the build time in RFC 3339, as stamping sets it.
	// String variables are all that the linker can set.
	buildTime = ""
)

func init() {
	if BuildTime.IsZero() {
		BuildTime = parseBuildTime(buildTime)
	}
}

// parseBuildTime parses an RFC 3339 time, and gives the zero time for an
// empty or bad one.
func parseBuildTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// Version returns a newline-terminated string describing the current
// version of the build.
func Version() string {
	if GitSHA == "" {
		return "devel\n"
	}
	str := ""
	if Release != "" {
		str += fmt.Sprintf("Release:    %s\n", Release)
	}
	if !BuildTime.IsZero() {
		str += fmt.Sprintf("Build time: %s\n", BuildTime.In(time.UTC).Format(time.Stamp+" 2006 UTC"))
	}
	str += fmt.Sprintf("Git hash:   %s\n", GitSHA)
	return str
}
