# Local copy of the FUSE library

This directory is a copy of `github.com/presotto/fuse` at commit
`944bbcc73d97d4d541858918651075fca183d088`.
It holds the packages upspinfs uses: `fuse`, `fs` and `fuseutil`.
The tests that need the upstream `fstestutil` package are left out.

upspinfs needs to keep a mount alive when its process dies
(https://github.com/filmil/upspin/issues/106).
That takes changes to private parts of the library, so upspin keeps its own
copy.
The first commit that added this directory holds the upstream files
unchanged, so `git log` shows every local change as a diff.

The upstream license is in `LICENSE`.

## Local changes

- `fuse.Adopt` serves the descriptor of a mount that is already initialized.
  It does not run INIT.
- `Conn.File` returns the descriptor, so another process can inherit it.
- `fs.Config.Observer` reports each change to the node and handle tables of
  `fs.Server`.
- `fs.Server.Restore` starts a server with the tables of an earlier one.
- An unreachable `panic` is gone, because `go vet` reports it.
