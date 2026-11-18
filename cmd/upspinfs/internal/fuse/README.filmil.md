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
