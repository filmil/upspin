# Changes in this fork

This file describes the feature improvements made in this fork of Upspin,
one section per feature.
The original project README is [README.md](README.md).
New features are described here rather than there, so the two stay
distinct.

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
