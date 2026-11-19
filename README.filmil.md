# Changes in this fork

This file describes the feature improvements made in this fork of Upspin,
one section per feature.
The original project README is [README.md](README.md).
New features are described here rather than there, so the two stay
distinct.
The same rule applies to every document: an original file such as
`doc/security.md` is never edited, and the fork's additions to it live
beside it in a file with the same base name and the extension
`.filmil.md`, such as `doc/security.filmil.md`.

## Local keyserver and per-domain key lookup

The central keyserver at `key.upspin.io` was turned off in 2025.
This fork lets you host your own keyserver and points clients at it.

* `cmd/local_keyserver` is a keyserver that loads its user records from a
  static JSON file given with `-json`.
  By default it is read-only.
  With `-out` it also accepts `Put` requests and saves the whole user set
  to that file, loading it as an overlay on the next start.
  Run it at `key.yourdomain.com`.
* The `bind` package looks up keys for `user@yourdomain.com` on
  `key.yourdomain.com:443` instead of `key.upspin.io`, so existing keys
  keep working once the domain runs its own keyserver.
* The `local_keyserver` binary ships in the release container image.

This is meant for people who already hold Upspin keys and want to
reactivate them; it is not a signup service for new users.
Releases 43.0.2 and later include it.
See [doc/revival/local_keyserver.md](doc/revival/local_keyserver.md) for
the JSON format and how to run the server.

## Post-quantum key wrapping: the eepq packing

The `eepq` packing protects data written from now on against an attacker
who stores ciphertext today and decrypts it once a quantum computer can
break elliptic curves.
It keeps the `ee` data encryption (AES-256), checksums and ECDSA
signatures, and changes only how the per-file key is wrapped for each
reader: the wrapping key is derived from both an ECDH shared secret and
an ML-KEM (FIPS 203) shared secret, with an HKDF concatenation combiner
in the style of X-Wing, so both must be broken to recover it.
The packing is opt-in: pass the `-eepq` flag to every binary that should
handle it, servers included.
A post-quantum public key has a fourth line that binaries from before
this change cannot parse, so upgrade every binary in the deployment
before anyone rotates to such a key.

* Key types pair a curve with the ML-KEM parameter set of matching
  strength: `p256+mlkem768`, `p384+mlkem768` or `p521+mlkem1024`.
  Generate one with `upspin keygen -curve p256+mlkem768`, or rotate to one
  with `upspin keygen -rotate -curve p256+mlkem768` and follow
  `upspin rotate -help`.
  A post-quantum key has a 256 bit secret seed of 16 proquint words, twice
  the classic length, as FIPS 203 requires; that seed restores both halves
  of the key.
* Set `packing: eepq` in the config file.
  `upspin signup` does this itself when given a post-quantum key type.
* Readers must also have a post-quantum key.
  Both `put` and `upspin share -fix` stop with an error naming a reader
  whose key is classic.
* `requirepacking: eepq` in the config makes the client refuse to write
  or read regular files under any other packing.
* A directory entry grows from about 263 bytes to about 1353 bytes for one
  `p256+mlkem768` reader, and each further reader adds 1251 bytes.
* Data written earlier under `ee` is not changed and should be treated as
  exposed; write it again under `eepq` if it must be protected.

See [doc/security.filmil.md](doc/security.filmil.md) for the scheme and
the key file formats, and [doc/config.filmil.md](doc/config.filmil.md)
for the settings.

## Config and key files as JSON

The config file and the key files may be written as JSON.
Every reader tries JSON first and falls back to the original format, so
a directory may hold files of either kind.
The writers (`upspin keygen`, `upspin signup`) still write the original
format, so that binaries from before this change keep reading what they
write.
A later release will switch the writers to JSON.

* **The config file** (`$HOME/upspin/config`, and the `config` file in a
  server's configuration directory) is a JSON object with the same keys:

  ```json
  {"username": "you@example.com", "secrets": "/home/you/.ssh",
   "packing": "ee", "cmdflags": {"upspinfs": {"cachedir": "/tmp"}}}
  ```

  A file that does not start with `{` is read as YAML, as before.
  A file that starts with `{` but is not valid JSON is read as YAML too,
  since YAML accepts more than JSON; if that fails as well, the error
  names both attempts.
* **`public.upspinkey`:**
  `{"type": "p256+mlkem768", "x": "...", "y": "...", "encapsulation_key": "..."}`.
  The fields are the lines of the original format, named.
  `encapsulation_key` is present only for a key type that names a KEM.
* **`secret.upspinkey`:** `{"d": "...", "kem_seed": "...", "secret_seed": "..."}`.
  `kem_seed` is present only for a key type that names a KEM; a mismatch
  with the type in `public.upspinkey` is an error when the keys load.
  `secret_seed` is optional; it records the proquint words that re-create
  the key, and is kept as the `# ...` comment of the original format, so
  a rotation keeps it in the archive.
* **`secret2.upspinkey`,** the archive of earlier key pairs:
  `{"keys": [{"date": "...", "public": {...}, "private": {...}}]}`,
  where `public` and `private` have the fields above.
  When `upspin keygen -rotate` adds a pair to an archive written as JSON,
  it first checks that the old keys load, then rewrites the archive in
  the original format through a temporary file and a rename.

A key file in JSON rejects fields it does not know, so a misspelled field
name is an error instead of an empty value.
Each key value must be one token of the original format: letters, digits
and the characters `+`, `/`, `=` and `-`.
Only the files change: the public key that goes over the wire, to the
keyserver and in directory entries, keeps its original form.

## upspinfs keeps its mount when its process dies

On Linux, upspinfs keeps its mount alive when the server process crashes
or is killed.
Without this, every access to the mount fails with "Transport endpoint is
not connected" until someone unmounts and starts upspinfs again.
`-supervise` is on by default on Linux; `-supervise=false` turns it off.
Other systems do not have it.

With `-supervise`, upspinfs runs as two processes.

* The supervisor mounts the file system and keeps the `/dev/fuse`
  descriptor, so the mount lives as long as the supervisor does.
  It starts the server as a child process, hands it the descriptor, and
  starts a new one when the child dies, after 1 to 30 seconds.
  It unmounts on SIGTERM or SIGINT.
* The server keeps its FUSE tables in a journal: the node and handle IDs
  the kernel holds, and the cache files of files written but not yet put
  to the store, with their encryption keys.
  The journal is a memory file (memfd) that the supervisor holds, so it
  never reaches a disk and ends with the mount.
* A new server restores the tables, so the kernel's node IDs and open
  files keep working.
  It puts the restored unsaved writes to the store at once, because a
  release in flight at the crash is lost.

Requests that the dead server had read and not answered fail with `EIO`.
The kernel would otherwise wait for them forever; Linux 6.9 and later could
resend them instead (`FUSE_NOTIFY_RESEND`), which upspinfs does not use yet.
The new server answers the 65536 request IDs below its first request with
`EIO`; the kernel ignores the ones it is not waiting for.
A lost request older than that still waits forever.

`-hang_timeout`, 1 minute by default, also restarts a server that lives but
stops answering; `-hang_timeout=0` turns it off.
The supervisor looks up a name that the server answers from memory, and
restarts the server when that lookup gets no answer in time while requests
are waiting.
It reads the waiting requests from `/sys/fs/fuse/connections`, so it needs
the fusectl file system mounted there; without it the flag is off and the
supervisor says so.

`cmd/upspinfs/killtest` kills the server in the middle of reads, writes and
concurrent requests, and stops it with SIGSTOP to test `-hang_timeout`.
It needs `/dev/fuse` and `fusermount`, starts real Upspin servers, and is
tagged manual:
`bazel test //cmd/upspinfs/killtest:killtest_test`.

Details: https://github.com/filmil/upspin/issues/106.

## The Bazel module: filmil_upspin

The Bazel module is named `filmil_upspin`, because this is a spin-off and
the name `upspin` belongs to the original project.
Releases up to 45.2.0 were published as `upspin` in the custom registry,
and stay there; later releases are published as `filmil_upspin`.

```starlark
bazel_dep(name = "filmil_upspin", version = "<version>")
```

Labels are then `@filmil_upspin//...`.
Add `repo_name = "upspin"` to write them as `@upspin//...`.

The Go module path is still `upspin.io`.
So one build cannot hold both this module and another copy of
`upspin.io`: not the original, and not an old `upspin` release of this
one.
Two Go packages with the same import path collide in `rules_go`.
A build that pulls in both, for example through two dependencies, must
move them all to `filmil_upspin`.

## Checks for Bazel Central Registry publication

The module is published to the Bazel Central Registry (BCR), and these
checks keep a release publishable.

* `integration/` is a separate Bazel module that depends on upspin, as an
  outside user would.
  Its test generates a key pair, then encrypts and decrypts a block with
  the `ee` packing; it reads no files.
  BCR presubmit runs it as the test module, on Debian 11, Ubuntu 22.04
  and 24.04, and macOS on x86-64 and arm64, with Bazel 8 and 9.
  Run it locally with
  `cd integration && bazel test --registry=https://bcr.bazel.build //...`.
* The upspin packages' own tests read their fixtures from the source tree,
  so they run only where upspin is the main module, not in BCR presubmit.
* CI resolves the module graph from BCR alone, ignoring `.bazelrc` and its
  custom registry, so a dependency that BCR does not have fails the build.
* CI runs the integration module on Linux and macOS with Bazel 8 and 9.
* `MODULE.bazel` declares `bazel_compatibility = [">=8.0.0"]`.
