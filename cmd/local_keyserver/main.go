// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Local_keyserver is a key server that takes its contents from a fixed JSON file.
package main

import (
	"flag"
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
)

func main() {
	flags.Parse(flags.Server)
	if *jsonFile == "" {
		log.Fatalf("must specify -json file")
	}

	f, err := os.Open(*jsonFile)
	if err != nil {
		log.Fatal(err)
	}
	key, err := inprocess.NewRO(f)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()

	cfg, err := config.FromFile(flags.Config)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/api/Key/", rpc.New(cfg, key, upspin.NetAddr(flags.NetAddr)))

	https.ListenAndServeFromFlags(nil)
}
