// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clientutil

import (
	"upspin.io/access"
	"upspin.io/errors"
	"upspin.io/pack"
	"upspin.io/upspin"
)

// RequiredPackingKey is the config key, "requirepacking", whose value names
// the packing every regular file must have. See CheckPacking.
const RequiredPackingKey = "requirepacking"

// RequiredPacking returns the packing named by the requirepacking config
// value. The boolean is false when the key is unset. A name that does not
// resolve to a registered packing is an error, never "no requirement":
// a typo must fail closed.
func RequiredPacking(cfg upspin.Config) (upspin.Packing, bool, error) {
	name := cfg.Value(RequiredPackingKey)
	if name == "" {
		return upspin.UnassignedPack, false, nil
	}
	p := pack.LookupByName(name)
	if p == nil {
		return upspin.UnassignedPack, false, errors.E(errors.Invalid, errors.Errorf("%s: unknown packing %q", RequiredPackingKey, name))
	}
	return p.Packing(), true, nil
}

// CheckPacking returns an errors.Permission error if the config names a
// required packing and entry, a regular file, has a different one, and an
// errors.Invalid error if the config names a packing that does not exist.
// Directories, links, and Access and Group files are exempt: directories
// are not packed, and access control files are written with an all-users
// wrap in whatever packing the writer's config names, so requiring one
// packing of them would lock out readers with other configs. The client
// calls it before writing, to catch a config whose packing was changed,
// and before reading, to refuse an entry served with a weaker packing
// than the user requires; upspinfs calls it before it unpacks a file.
func CheckPacking(cfg upspin.Config, entry *upspin.DirEntry) error {
	want, ok, err := RequiredPacking(cfg)
	if err != nil {
		return err
	}
	if !ok || entry.IsDir() || entry.IsLink() || access.IsAccessControlFile(entry.SignedName) {
		return nil
	}
	if entry.Packing != want {
		return errors.E(errors.Permission, entry.Name, errors.Errorf("packing %s; config requires %s", entry.Packing, want))
	}
	return nil
}
