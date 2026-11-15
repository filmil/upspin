// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"

	"upspin.io/subcmd"
	"upspin.io/upspin"
)

func (s *State) listrefs(args ...string) {
	const help = `
Listrefs prints the storage reference of every block of each regular file
named, one block per line: the reference, the store endpoint and the path
name, separated by tabs. Links are not followed, and directories are
descended only with -r.

Its purpose is to record the blocks of files before repack rewrites them,
because repack leaves the old blocks in the store. Once the repacked files
are checked, the saved references can be given to deletestorage:

	upspin listrefs -r me@example.com/ > refs.txt
	upspin repack -pack eepq -r me@example.com/
	cut -f1 refs.txt | xargs upspin deletestorage -ref

Deletestorage assumes that each reference is on the user's own store; the
second column shows when that is not so. Read deletestorage -help first:
a block that another path name or a snapshot still refers to must not be
deleted.
`
	fs := flag.NewFlagSet("listrefs", flag.ExitOnError)
	fs.Bool("r", false, "recur into subdirectories")
	s.ParseFlags(fs, args, help, "listrefs [-r] path...")
	if fs.NArg() == 0 {
		usageAndExit(fs)
	}
	recur := subcmd.BoolFlag(fs, "r")
	for _, entry := range s.GlobAllUpspin(fs.Args()) {
		s.listrefsEntry(entry, recur)
	}
}

// listrefsEntry prints the block references of entry. If entry is a
// directory and recur is set, it descends.
func (s *State) listrefsEntry(entry *upspin.DirEntry, recur bool) {
	switch {
	case entry.IsDir():
		if !recur {
			s.Exitf("%q is a directory; use -r", entry.Name)
		}
		entries, err := s.Client.Glob(upspin.AllFilesGlob(entry.Name))
		if err != nil {
			s.Exit(err)
		}
		for _, e := range entries {
			s.listrefsEntry(e, true)
		}
	case entry.IsLink():
		// A link has no blocks of its own.
	default:
		for _, b := range entry.Blocks {
			fmt.Fprintf(s.Stdout, "%s\t%s\t%s\n", b.Location.Reference, b.Location.Endpoint, entry.Name)
		}
	}
}
