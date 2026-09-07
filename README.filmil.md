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
