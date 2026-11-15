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
name, separated by tabs. A link named on the command line or found in a
tree is skipped, since it has no blocks of its own; links in the middle of
a path name are followed. Directories are descended only with -r. A file
whose blocks the user cannot see (no read access) is an error.

Its purpose is to find the blocks that repack leaves behind. Repack writes
new blocks and does not delete the old ones; deletestorage does. Record
the references before and after repack, and delete only those that are
gone afterwards. Files that repack does not rewrite, such as Access and
Group files and files already in the requested packing, keep their blocks,
which then appear in both lists and must not be deleted:

	upspin listrefs -r me@example.com/ | cut -f1,2 | sort -u > before.txt
	upspin repack -pack eepq -r me@example.com/
	upspin listrefs -r me@example.com/ | cut -f1,2 | sort -u > after.txt
	comm -23 before.txt after.txt > gone.txt

Deletestorage -ref assumes the user's own store, so keep only the lines
of gone.txt whose second field is that store, then pass the first field:

	cut -f1 gone.txt | xargs -r upspin deletestorage -ref

Read deletestorage -help first: a block that another user's tree or a
snapshot still refers to must not be deleted.
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
// directory and recur is set, it descends. Errors are reported and the
// walk goes on; the exit status is then 1.
func (s *State) listrefsEntry(entry *upspin.DirEntry, recur bool) {
	switch {
	case entry.IsDir():
		if !recur {
			s.Failf("%q is a directory; use -r", entry.Name)
			return
		}
		entries, err := s.Client.Glob(upspin.AllFilesGlob(entry.Name))
		if err != nil {
			s.Fail(err)
			return
		}
		for _, e := range entries {
			s.listrefsEntry(e, true)
		}
	case entry.IsLink():
		// A link has no blocks of its own.
	case entry.IsIncomplete():
		s.Failf("%q: no read access, so its blocks are not known", entry.Name)
	default:
		for _, b := range entry.Blocks {
			fmt.Fprintf(s.Stdout, "%s\t%s\t%s\n", b.Location.Reference, b.Location.Endpoint, entry.Name)
		}
	}
}
