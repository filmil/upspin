# Configuration: additions in this fork

This file holds the additions this fork makes to
[doc/config.md](config.md).
That file is the original Upspin text and is left as the original
authors wrote it.
The settings below were added for the `eepq` packing; see
[security.filmil.md](security.filmil.md) for the scheme.

## Settings

* The **`packing`** setting accepts one more value, `eepq`, which is `ee`
  with post-quantum key wrapping.
  It combines elliptic curve key agreement with ML-KEM, so that data
  written under it stays confidential against an attacker with a quantum
  computer.
  It requires a key whose type names a KEM, such as `p256+mlkem768`, and
  the `-eepq` command line flag on every command that uses it.
* The **`experimental`** setting lists opt-in features, separated by
  commas or spaces.
  `experimental: eepq` enables the post-quantum packing for every command
  that reads the config, the same switch the `-eepq` flag sets, so the
  flag is not needed on every invocation.
  `upspin signup` writes it next to `packing: eepq` when given a
  post-quantum key type.
  Any other name is an error.
* The **`requirepacking`** setting names a packing that every regular
  file must have.
  The client refuses to write a file under another packing and refuses to
  read a file served with another packing, except for files already in
  the `upspinfs` cache.
  Directories, links, and Access and Group files are exempt.
  It is unset by default.
