// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Local_keyserver is a key server that takes its contents from a fixed JSON file.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"os"

	"upspin.io/cloud/https"
	"upspin.io/config"
	"upspin.io/flags"
	"upspin.io/key/inprocess"
	"upspin.io/log"
	rpc "upspin.io/rpc/keyserver"
	"upspin.io/upspin"

	_ "upspin.io/key/transports"
)

var (
	jsonFile = flag.String("json", "", "JSON file containing user keys")
	writable = flag.Bool("writable", false, "allow updates to the user keys")
	outFile  = flag.String("out", "", "JSON file where new keys are written (defaults to -json)")
)

func main() {
	flags.Parse(flags.Server)
	if *jsonFile == "" {
		log.Fatalf("must specify -json file")
	}
	out := *outFile
	if out == "" {
		out = *jsonFile
	}

	f, err := os.Open(*jsonFile)
	if err != nil {
		log.Fatal(err)
	}
	key, err := inprocess.NewRW(f, !*writable)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()

	if *writable && *outFile != "" {
		// If a separate out file is specified, load it as an overlay if it exists.
		f, err := os.Open(*outFile)
		if err == nil {
			type filler interface {
				Fill(io.Reader) error
			}
			if err := key.(filler).Fill(f); err != nil {
				log.Fatalf("loading %s: %v", *outFile, err)
			}
			f.Close()
		} else if !os.IsNotExist(err) {
			log.Fatal(err)
		}
	}

	if *writable {
		key = &persistentServer{
			KeyServer: key,
			file:      out,
		}
	}

	cfg, err := config.FromFile(flags.Config)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/api/Key/", rpc.New(cfg, key, upspin.NetAddr(flags.NetAddr)))

	https.ListenAndServeFromFlags(nil)
}

type persistentServer struct {
	upspin.KeyServer
	file string
}

func (s *persistentServer) Put(u *upspin.User) error {
	if err := s.KeyServer.Put(u); err != nil {
		return err
	}
	// Save to file.
	type userGetter interface {
		Users() ([]upspin.User, error)
	}
	users, err := s.KeyServer.(userGetter).Users()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(inprocess.KeyData{Users: users}, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(s.file, data, 0600)
}
