// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rpc

import (
	goerrors "errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/golang/protobuf/proto"

	"upspin.io/errors"
)

func TestResult(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "ok"},
		{errors.E(errors.Invalid, "x"), "invalid"},
		{errors.E(errors.Permission, "x"), "permission"},
		{errors.E(errors.IO, "x"), "io"},
		{errors.E(errors.Exist, "x"), "exist"},
		{errors.E(errors.NotExist, "x"), "not_exist"},
		{errors.E(errors.IsDir, "x"), "is_dir"},
		{errors.E(errors.NotDir, "x"), "not_dir"},
		{errors.E(errors.NotEmpty, "x"), "not_empty"},
		{errors.E(errors.Private, "x"), "private"},
		{errors.E(errors.Internal, "x"), "internal"},
		{errors.E(errors.CannotDecrypt, "x"), "cannot_decrypt"},
		{errors.E(errors.Transient, "x"), "transient"},
		{errors.E(errors.BrokenLink, "x"), "broken_link"},
		{errors.E(errors.Other, "x"), "other"},
		{errors.Str("plain"), "other"},
		{goerrors.New("not an upspin error"), "other"},
		{fmt.Errorf("wrapped: %w", errors.E(errors.NotExist, "x")), "not_exist"},
	} {
		if got := Result(tc.err); got != tc.want {
			t.Errorf("Result(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

type observation struct {
	service, method, result string
	d                       time.Duration
}

// observe sets RequestObserver for one test and returns what it records.
func observe(t *testing.T) *[]observation {
	t.Helper()
	var got []observation
	old := RequestObserver
	RequestObserver = func(service, method, result string, d time.Duration) {
		got = append(got, observation{service, method, result, d})
	}
	t.Cleanup(func() { RequestObserver = old })
	return &got
}

func TestServeHTTPObserves(t *testing.T) {
	s := &serverImpl{service: Service{
		Name: "Test",
		Methods: map[string]Method{
			"Auth": func(Session, []byte) (pb.Message, error) { return nil, nil },
		},
		UnauthenticatedMethods: map[string]UnauthenticatedMethod{
			"Ok":   func([]byte) (pb.Message, error) { return nil, nil },
			"Fail": func([]byte) (pb.Message, error) { return nil, errors.E(errors.Permission, "no") },
		},
		Streams: map[string]Stream{
			"Watch": func(Session, []byte, <-chan struct{}) (<-chan pb.Message, error) {
				return nil, errors.E(errors.Invalid, "no stream")
			},
		},
	}}
	got := observe(t)
	for _, tc := range []struct {
		path, result string // result "" means not observed
	}{
		{"/api/Test/Ok", "ok"},
		{"/api/Test/Fail", "permission"},
		{"/api/Test/Auth", "unauthenticated"}, // No auth headers.
		{"/api/Test/Watch", "unauthenticated"},
		{"/api/Test/NoSuchMethod", ""},
		{"/api/Other/Ok", ""},
	} {
		*got = nil
		s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", tc.path, strings.NewReader("")))
		switch {
		case tc.result == "" && len(*got) != 0:
			t.Errorf("%s: observed %+v, want nothing", tc.path, *got)
		case tc.result != "" && (len(*got) != 1 || (*got)[0].result != tc.result || (*got)[0].service != "Test"):
			t.Errorf("%s: observed %+v, want one %q", tc.path, *got, tc.result)
		}
	}
}
