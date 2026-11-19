// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

package main

import (
	_ "expvar"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"upspin.io/cmd/cacheserver/cacheutil"
	"upspin.io/config"
	"upspin.io/flags"
	"upspin.io/log"
	"upspin.io/rpc/local"
	"upspin.io/version"

	_ "upspin.io/pack/ee"
	_ "upspin.io/pack/eeintegrity"
	_ "upspin.io/pack/plain"

	"upspin.io/transports"
)

const cmdName = "upspinfs"

var (
	mountpointFlag = flag.String("mountpoint", "", "`directory` on which to mount file system")
	allowOther     = flag.Bool("allow_other", false, "if set, allow other users to see the mount point; if using this option ensure that mount point access is strictly controlled")
	superviseFlag  = flag.Bool("supervise", false, "if set, keep the mount alive when the server process dies, and restart it (Linux only)")
	hangTimeout    = flag.Duration("hang_timeout", 0, "with -supervise, restart the server when a lookup of the user's root gets no answer for this `duration`; 0 turns it off")

	// Set by the supervisor for the server process it starts.
	fuseFDFlag    = flag.Int("fuse_fd", -1, "internal: `descriptor` of a mounted /dev/fuse to serve")
	fuseProtoFlag = flag.String("fuse_proto", "", "internal: FUSE protocol `version` of the -fuse_fd mount")
	journalFDFlag = flag.Int("journal_fd", -1, "internal: `descriptor` of the journal of the FUSE tables")
	fuseProbeFlag = flag.String("fuse_probe", "", "internal: look up `path` and exit")
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [-mountpoint] <mount point>\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flags.Parse(flags.Server, "cachedir", "cachesize", "prudent", "version")

	if flags.Version {
		fmt.Print(version.Version())
		return
	}
	if *fuseProbeFlag != "" {
		// Started by the supervisor; see probe.
		os.Stat(*fuseProbeFlag)
		return
	}

	// Normal setup, get configuration from file and push user cache onto config.
	cfg, err := config.FromFile(flags.Config)
	if err != nil {
		log.Debug.Fatal(err)
	}

	// Set any flags contained in the config.
	if err := config.SetFlagValues(cfg, cmdName); err != nil {
		log.Fatalf("%s: %s", cmdName, err)
	}

	transports.Init(cfg)

	if *mountpointFlag != "" {
		if flag.NArg() > 0 {
			log.Fatalf("mount point specified as both flag and argument\n")
		}
	} else {
		if flag.NArg() != 1 {
			usage()
			os.Exit(2)
		}
		*mountpointFlag = flag.Arg(0)
	}
	mountpoint, err := filepath.Abs(*mountpointFlag)
	if err != nil {
		log.Fatalf("can't determine absolute path to mount point %s: %s", *mountpointFlag, err)
	}

	if *superviseFlag {
		os.Exit(supervise(cfg, mountpoint, *allowOther, *hangTimeout, argsWithout(os.Args[1:], "supervise")))
	}

	// Start the cacheserver if needed.
	if cacheutil.Start(cfg) {
		// Using a cacheserver, adjust cache size for upspinfs down.
		flags.CacheSize = flags.CacheSize / 10
	}

	// Mount the file system, or take over a supervisor's, and serve it.
	cacheDir := filepath.Join(flags.CacheDir, string(cfg.UserName()))
	var done chan bool
	if *fuseFDFlag >= 0 {
		done = doAdopted(cfg, mountpoint, cacheDir, flags.CacheSize, *fuseFDFlag, *fuseProtoFlag, *journalFDFlag)
	} else {
		done = do(cfg, mountpoint, cacheDir, flags.CacheSize, *allowOther)
	}

	// Serve expvar data.
	ln, err := local.Listen("tcp", config.LocalName(cfg, cmdName))
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		ErrorLog: log.NewStdLogger(log.Debug),
	}
	go func() {
		log.Fatal(srv.Serve(ln))
	}()

	// Wait for an unmount.
	<-done
	srv.Close()
}

// argsWithout returns args without the boolean flag name, in any of its
// forms: -name, --name, -name=value.
func argsWithout(args []string, name string) []string {
	var out []string
	for i, a := range args {
		if a == "--" {
			return append(out, args[i:]...)
		}
		trimmed := strings.TrimLeft(a, "-")
		if len(trimmed) < len(a) && (trimmed == name || strings.HasPrefix(trimmed, name+"=")) {
			continue
		}
		out = append(out, a)
	}
	return out
}
