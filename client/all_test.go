// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"
	"testing/iotest"

	"upspin.io/bind"
	"upspin.io/client/clientutil"
	"upspin.io/config"
	"upspin.io/factotum"
	"upspin.io/flags"
	"upspin.io/log"
	"upspin.io/pack"
	"upspin.io/test/testutil"
	"upspin.io/upspin"

	dirserver "upspin.io/dir/inprocess"
	keyserver "upspin.io/key/inprocess"
	storeserver "upspin.io/store/inprocess"

	"upspin.io/errors"
)

var baseCfg upspin.Config
var baseCfg2 upspin.Config

func init() {
	inProcess := upspin.Endpoint{
		Transport: upspin.InProcess,
		NetAddr:   "", // ignored
	}

	// Create baseCfg with user1's keys.
	f, err := factotum.NewFromDir(testutil.Repo("key", "testdata", "user1")) // Always use user1's keys.
	if err != nil {
		panic("cannot initialize factotum: " + err.Error())
	}

	baseCfg = config.New()
	baseCfg = config.SetPacking(baseCfg, upspin.EEPack)
	baseCfg = config.SetKeyEndpoint(baseCfg, inProcess)
	baseCfg = config.SetStoreEndpoint(baseCfg, inProcess)
	baseCfg = config.SetDirEndpoint(baseCfg, inProcess)
	baseCfg = config.SetFactotum(baseCfg, f)

	// Create baseCfg2 with joe's keys.
	f, err = factotum.NewFromDir(testutil.Repo("key", "testdata", "test")) // Always use test's keys.
	if err != nil {
		panic("cannot initialize factotum: " + err.Error())
	}

	baseCfg2 = config.New()
	baseCfg2 = config.SetPacking(baseCfg, upspin.EEPack)
	baseCfg2 = config.SetKeyEndpoint(baseCfg, inProcess)
	baseCfg2 = config.SetStoreEndpoint(baseCfg, inProcess)
	baseCfg2 = config.SetDirEndpoint(baseCfg, inProcess)
	baseCfg2 = config.SetFactotum(baseCfg, f)

	bind.RegisterKeyServer(upspin.InProcess, keyserver.New())
	bind.RegisterStoreServer(upspin.InProcess, storeserver.New())
	bind.RegisterDirServer(upspin.InProcess, dirserver.New(baseCfg))
}

func checkTransport(s upspin.Service) {
	if s == nil {
		panic(fmt.Sprintf("nil service"))
	}
	if t := s.Endpoint().Transport; t != upspin.InProcess {
		panic(fmt.Sprintf("bad transport %v, want inprocess", t))
	}
}

func setup(base upspin.Config, userName upspin.UserName) upspin.Config {
	cfg := config.SetUserName(base, userName)
	key, _ := bind.KeyServer(cfg, cfg.KeyEndpoint())
	checkTransport(key)
	dir, _ := bind.DirServer(cfg, cfg.DirEndpoint())
	checkTransport(dir)
	if cfg.Factotum().PublicKey() == "" {
		panic("empty public key")
	}
	user := &upspin.User{
		Name:      upspin.UserName(userName),
		Dirs:      []upspin.Endpoint{cfg.DirEndpoint()},
		Stores:    []upspin.Endpoint{cfg.StoreEndpoint()},
		PublicKey: cfg.Factotum().PublicKey(),
	}
	err := key.Put(user)
	if err != nil {
		panic(err)
	}
	name := upspin.PathName(userName) + "/"
	entry := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Attr:       upspin.AttrDirectory,
		Writer:     userName,
	}
	_, err = dir.Put(entry)
	if err != nil && !errors.Is(errors.Exist, err) {
		panic(err)
	}
	return cfg
}

func TestPutGetTopLevelFile(t *testing.T) {
	const (
		user = "user1@google.com"
		root = user + "/"
	)
	client := New(setup(baseCfg, user))
	const (
		fileName = root + "file"
		text     = "hello sailor"
	)
	_, err := client.Put(fileName, []byte(text))
	if err != nil {
		t.Fatal("put file:", err)
	}
	data, err := client.Get(fileName)
	if err != nil {
		t.Fatal("get file:", err)
	}
	if string(data) != text {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, text)
	}
}

func TestPutSequencedGetTopLevelFile(t *testing.T) {
	const (
		user = "user1@google.com"
		root = user + "/"
	)
	client := New(setup(baseCfg, user))
	const (
		fileName = root + "file"
		text     = "hello sailor"
		text2    = "put your lips together and blow"
	)
	// Put the initial version, remembering the sequence.
	d, err := client.PutSequenced(fileName, upspin.SeqIgnore, []byte(text))
	if err != nil {
		t.Fatal("put file:", err)
	}
	data, err := client.Get(fileName)
	if err != nil {
		t.Fatal("get file:", err)
	}
	if string(data) != text {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, text)
	}
	seq := d.Sequence
	// PutSequenced another version using that sequence number. This should work.
	d, err = client.PutSequenced(fileName, seq, []byte(text2))
	if err != nil {
		t.Fatal("put file:", err)
	}
	if d.Sequence == seq {
		t.Fatalf("sequence number should have advanced")
	}
	data, err = client.Get(fileName)
	if err != nil {
		t.Fatal("get file:", err)
	}
	if string(data) != text2 {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, text2)
	}
	// Now try it a PutSequenced with the old sequence number. This should fail.
	_, err = client.PutSequenced(fileName, seq, []byte(text))
	if err == nil {
		t.Fatalf("PutSequenced with wrong sequence number should have failed")
	}
	// Make sure the data didn't change.
	data, err = client.Get(fileName)
	if err != nil {
		t.Fatal("get file:", err)
	}
	if string(data) != text2 {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, text2)
	}
}

const Max = 100 * 1000 // Must be > 100.

func setupFileIO(user upspin.UserName, fileName upspin.PathName, max int, t *testing.T) (upspin.Client, upspin.File, []byte) {
	client := New(setup(baseCfg, user))
	f, err := client.Create(fileName)
	if err != nil {
		t.Fatal("create file:", err)
	}

	// Create a data set with each byte equal to its offset.
	data := make([]byte, max)
	for i := range data {
		data[i] = uint8(i)
	}
	return client, f, data
}

func TestIotest(t *testing.T) {
	const (
		user     = "iotest@example.com"
		fileName = user + "/" + "file"
	)
	client, f, data := setupFileIO(user, fileName, 100, t)
	n, err := f.Write(data)
	if err != nil {
		t.Fatalf("Write(%d): %v", len(data), err)
	}
	if n != len(data) {
		t.Fatalf("Write length failed: expected %d got %d", len(data), n)
	}
	err = f.Close()
	if err != nil {
		t.Fatal(err)
	}

	f, err = client.Open(fileName)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = iotest.TestReader(f, data)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFileSequentialAccess(t *testing.T) {
	const (
		user     = "user3@google.com"
		fileName = user + "/" + "file"
	)
	client, f, data := setupFileIO(user, fileName, Max, t)

	// Write the file in randomly sized chunks until it's full.
	for offset, length := 0, 0; offset < Max; offset += length {
		// Pick a random length.
		length = rand.Intn(Max / 100)
		if offset+length > Max {
			length = Max - offset
		}
		n, err := f.Write(data[offset : offset+length])
		if err != nil {
			t.Fatalf("Write(offset %d length %d): %v", offset, length, err)
		}
		if n != length {
			t.Fatalf("Write length failed: offset %d expected %d got %d", offset, length, n)
		}
	}
	err := f.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Now read it back with a similar scan.
	f, err = client.Open(fileName)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, Max)
	for offset, length := 0, 0; offset < Max; offset += length {
		length = rand.Intn(Max / 100)
		if offset+length > Max {
			length = Max - offset
		}
		n, err := f.Read(buf[offset : offset+length])
		if err != nil {
			t.Fatalf("Read(offset %d length %d): %v", offset, length, err)
		}
		if n != length {
			t.Fatalf("Read length failed: offset %d expected %d got %d", offset, length, n)
		}
		for i := offset; i < offset+length; i++ {
			if buf[i] != data[i] {
				t.Fatalf("Read at %d (%#x): expected %#.2x got %#.2x", i, i, data[i], buf[i])
			}
		}
	}
}

func TestFileRandomAccess(t *testing.T) {
	// Use a much smaller block size for this test, and not a multiple of
	// block cipher buffer length (512) to shake out block boundary issues.
	oldBlockSize := flags.BlockSize
	flags.BlockSize = 1023
	defer func() {
		flags.BlockSize = oldBlockSize
	}()

	const (
		user     = "user4@google.com"
		root     = user + "/"
		fileName = root + "file"
	)
	client, f, data := setupFileIO(user, fileName, Max, t)

	// Use WriteAt at random offsets and random sizes to create file.
	// Start with a map of bools (easy) saying the byte has been written.
	// Loop until its length is the file size, meaning every byte has been written.
	written := make(map[int]bool)
	for len(written) != Max {
		// Pick a random offset and length.
		offset := rand.Intn(Max)
		// Don't bother starting at a known location - speeds up the coverage.
		for written[offset] {
			offset = rand.Intn(Max)
		}
		length := rand.Intn(Max / 100)
		if offset+length > Max {
			length = Max - offset
		}
		n, err := f.WriteAt(data[offset:offset+length], int64(offset))
		if err != nil {
			t.Fatalf("WriteAt(offset %d length %d): %v", offset, length, err)
		}
		if n != length {
			t.Fatalf("WriteAt length failed: offset %d expected %d got %d", offset, length, n)
		}
		for i := offset; i < offset+length; i++ {
			written[i] = true
		}
	}
	err := f.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Read file back all at once, for simple verification.
	f, err = client.Open(fileName)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	result := make([]byte, Max)
	n, err := f.Read(result)
	if err != nil {
		t.Fatal(err)
	}
	if n != Max {
		t.Fatalf("Read: expected %d got %d", Max, n)
	}
	if !bytes.Equal(data, result) {
		for i, c := range data {
			if result[i] != c {
				t.Fatalf("byte at offset %d should be %#.2x is %#.2x", i, c, result[i])
			}
		}
	}
	_, err = f.ReadAt(result, 1)
	if err == nil {
		t.Fatal("expected err==io.EOF from ReadAt, got err==nil")
	}

	// Now use a similar algorithm to WriteAt but with ReadAt to check random access.
	read := make(map[int]bool)
	buf := make([]byte, Max)
	for len(read) != Max {
		// Pick a random offset and length.
		offset := rand.Intn(Max)
		// Don't bother starting at a known location - speeds up the coverage.
		for read[offset] {
			offset = rand.Intn(Max)
		}
		length := rand.Intn(Max / 100)
		if offset+length > Max {
			length = Max - offset
		}
		n, err := f.ReadAt(buf[offset:offset+length], int64(offset))
		if err != nil {
			t.Fatalf("ReadAt(offset %d length %d): %v", offset, length, err)
		}
		if n != length {
			t.Fatalf("ReadAt length failed: offset %d expected %d got %d", offset, length, n)
		}
		for i := offset; i < offset+length; i++ {
			if buf[i] != data[i] {
				t.Fatalf("ReadAt at %d (%#x): expected %#.2x got %#.2x", i, i, data[i], buf[i])
			}
		}
		for i := offset; i < offset+length; i++ {
			read[i] = true
		}
	}
}

func TestFileSeek(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestFileSeek in short mode.")
	}
	const (
		user     = "fileseek@google.com"
		root     = user + "/"
		fileName = root + "file"
	)
	client, f, data := setupFileIO(user, fileName, Max, t)

	// Seek to random offsets and Write random sizes to create file.
	// Start with a map of bools (easy) saying the byte has been written.
	// Loop until its length is the file size, meaning every byte has been written.
	written := make(map[int]bool)
	// Initial offset start of file.
	curOffset := int64(0)
	for len(written) != Max {
		// Cycle for each whence value.
		for whence := 0; whence < 3; whence++ {
			// Pick a random offset and length.
			offset := rand.Intn(Max)
			// Don't bother starting at a known location - speeds up the coverage.
			for written[offset] {
				offset = rand.Intn(Max)
			}
			length := rand.Intn(Max / 100)
			if offset+length > Max {
				length = Max - offset
			}
			seekOffset := int64(offset)
			switch whence {
			case 1:
				seekOffset -= curOffset
			case 2:
				// Seek to end of file first, so we know current file length.
				fLen, err := f.Seek(0, whence)
				if err != nil {
					t.Fatalf("Seek(0, whence %d): %v", whence, err)
				}
				seekOffset -= fLen
			}
			o, err := f.Seek(seekOffset, whence)
			if err != nil {
				t.Fatalf("Seek(offset %d, whence %d): %v", seekOffset, whence, err)
			}
			if o != int64(offset) {
				t.Fatalf("Seek failed (whence %d): expected offset %d got %d", whence, offset, o)
			}
			n, err := f.Write(data[offset : offset+length])
			if err != nil {
				t.Fatalf("Write(length %d): %v", length, err)
			}
			if n != length {
				t.Fatalf("Write length failed: offset %d expected %d got %d", offset, length, n)
			}
			curOffset = o + int64(length)
			for i := offset; i < offset+length; i++ {
				written[i] = true
			}
			// Avoid entering an infinite loop above
			if len(written) == Max {
				break
			}
		}
	}
	err := f.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Read file back all at once, for simple verification.
	f, err = client.Open(fileName)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	result := make([]byte, Max)
	n, err := f.Read(result)
	if err != nil {
		t.Fatal(err)
	}
	if n != Max {
		t.Fatalf("Read: expected %d got %d", Max, n)
	}
	if !bytes.Equal(data, result) {
		for i, c := range data {
			if result[i] != c {
				t.Fatalf("byte at offset %d should be %#.2x is %#.2x", i, c, result[i])
			}
		}
	}

	// Now use a similar algorithm to Write but with Read to check random access.
	read := make(map[int]bool)
	buf := make([]byte, Max)
	curOffset = int64(0)
	for len(read) != Max {
		// Cycle for each whence value.
		for whence := 0; whence < 3; whence++ {
			// Pick a random offset and length.
			offset := rand.Intn(Max)
			// Don't bother starting at a known location - speeds up the coverage.
			for read[offset] {
				offset = rand.Intn(Max)
			}
			length := rand.Intn(Max / 100)
			if offset+length > Max {
				length = Max - offset
			}
			seekOffset := int64(offset)
			switch whence {
			case 1:
				seekOffset -= curOffset
			case 2:
				seekOffset -= Max
			}
			o, err := f.Seek(seekOffset, whence)
			if err != nil {
				t.Fatalf("Seek(offset %d, whence %d): %v", seekOffset, whence, err)
			}
			if o != int64(offset) {
				t.Fatalf("Seek failed (whence %d): expected offset %d got %d", whence, offset, o)
			}
			n, err := f.Read(buf[offset : offset+length])
			if err != nil {
				t.Fatalf("Read(offset %d, length %d): %v", offset, length, err)
			}
			if n != length {
				t.Fatalf("Read length failed: offset %d expected %d got %d", offset, length, n)
			}
			for i := offset; i < offset+length; i++ {
				if buf[i] != data[i] {
					t.Fatalf("ReadAt at %d (%#x): expected %#.2x got %#.2x", i, i, data[i], buf[i])
				}
			}
			curOffset = o + int64(length)
			for i := offset; i < offset+length; i++ {
				read[i] = true
			}
			// Avoid entering an infinite loop above
			if len(read) == Max {
				break
			}
		}
	}
}

func TestFileZeroFill(t *testing.T) {
	const (
		user     = "zerofill@google.com"
		fileName = user + "/" + "file"
	)
	client, _, _ := setupFileIO(user, fileName, 0, t)
	// Create and write one byte 100 bytes out.
	f, err := client.Create(fileName)
	if err != nil {
		t.Fatal("create file:", err)
	}
	const N = 100
	n64, err := f.Seek(N, 0)
	if err != nil {
		t.Fatal("seek file:", err)
	}
	if n64 != N {
		t.Fatalf("seek file: expected %d got %d", N, n64)
	}
	n, err := f.Write([]byte{'x'})
	if err != nil {
		t.Fatal("write file:", err)
	}
	if n != 1 {
		t.Fatalf("write file: expected %d got %d", 1, n)
	}
	f.Close()
	// Read it back.
	f, err = client.Open(fileName)
	if err != nil {
		t.Fatal("open file:", err)
	}
	defer f.Close()
	buf := make([]byte, 2*N) // Much more than was written.
	// Make it all non-zero.
	for i := range buf {
		buf[i] = 'y'
	}
	n, err = f.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal("read file:", err)
	}
	if n != N+1 {
		t.Fatalf("read file: expected %d got %d", N+1, n)
	}
	for i := 0; i < N; i++ {
		if buf[i] != 0 {
			t.Errorf("byte %d should be 0 is %#.2x", i, buf[i])
		}
	}
	if buf[N] != 'x' {
		t.Errorf("byte %d should be 'x' is %#.2x", N, buf[N])
	}
}

func globAndCheck(t *testing.T, client upspin.Client, pattern string, expect ...upspin.PathName) bool {
	entries, err := client.Glob(pattern)
	if err != nil {
		t.Errorf("Glob(%q): err = %v; expected none", pattern, err)
		return false
	}
	if len(entries) != len(expect) {
		t.Errorf("Glob(%q): got %d entries, expected %d:", pattern, len(entries), len(expect))
		for _, entry := range entries {
			t.Logf("\t%s", entry.Name)
		}
		return false
	}
	for i, p := range expect {
		if entries[i].Name != p {
			t.Errorf("Glob(%q): index %d: got %q; expected %q", pattern, i, p, entries[i].Name)
			return false
		}
	}
	return true
}

func TestGlob(t *testing.T) {
	const user = "multiuser@a.co"
	client := New(setup(baseCfg, user))
	var err error

	for _, fno := range []int{0, 1, 7, 17} {
		fileName := fmt.Sprintf("%s/testfile%d.txt", user, fno)
		text := fmt.Sprintf("Contents of file %s", fileName)
		_, err = client.Put(upspin.PathName(fileName), []byte(text))
		if err != nil {
			t.Fatal("put file:", err)
		}
	}

	if !globAndCheck(t, client, "multiuser@a.co/testfile*.txt",
		"multiuser@a.co/testfile0.txt", "multiuser@a.co/testfile1.txt", "multiuser@a.co/testfile17.txt", "multiuser@a.co/testfile7.txt") {
		t.Error("glob failed")
	}
	if !globAndCheck(t, client, "multiuser@a.co/*7.txt",
		"multiuser@a.co/testfile17.txt", "multiuser@a.co/testfile7.txt") {
		t.Error("glob failed")
	}
	if !globAndCheck(t, client, "multiuser@a.co/*1*.txt",
		"multiuser@a.co/testfile1.txt", "multiuser@a.co/testfile17.txt") {
		t.Error("glob failed")
	}

}

func TestPutDuplicateAndRename(t *testing.T) {
	const user = "link@a.com"
	client := New(setup(baseCfg, user))
	original := upspin.PathName(fmt.Sprintf("%s/original", user))
	text := "the rain in spain"
	if _, err := client.Put(original, []byte(text)); err != nil {
		t.Fatal("put file:", err)
	}

	// Duplicate: create a new name for the same reference.
	dup := upspin.PathName(fmt.Sprintf("%s/dup", user))
	entry, err := client.PutDuplicate(original, dup)
	if err != nil {
		t.Fatal("duplicate file:", err)
	}
	if entry == nil {
		t.Fatal("nil entry returned by PutDuplicate")
	}
	if entry.Name != dup {
		t.Fatal("duped directory entry has wrong name")
	}
	in, err := client.Get(original)
	if err != nil {
		t.Fatal("get file:", err)
	}
	if string(in) != text {
		t.Fatal(fmt.Sprintf("contents of %q corrupted", original))
	}
	in, err = client.Get(dup)
	if err != nil {
		t.Fatal("get file:", err)
	}
	if string(in) != text {
		t.Fatal(fmt.Sprintf("contents of %q and %q don't match", original, dup))
	}

	// Rename the new file.
	renamed := upspin.PathName(fmt.Sprintf("%s/renamed", user))
	if _, err := client.Rename(dup, renamed); err != nil {
		t.Fatal("link file:", err)
	}
	if _, err := client.Get(dup); err == nil {
		t.Fatal("renamed file still exists")
	}
	in, err = client.Get(renamed)
	if err != nil {
		t.Fatal("get file:", err)
	}
	if string(in) != text {
		t.Fatal(fmt.Sprintf("contents of %q and %q don't match", renamed, original))
	}
}
func TestPutDuplicateDifferentUser(t *testing.T) {
	t.Run(fmt.Sprintf("packing=ee"), func(t *testing.T) {
		testPutDuplicateDifferentUser(t, upspin.EEPack)
	})
	t.Run(fmt.Sprintf("packing=eeintegrity"), func(t *testing.T) {
		testPutDuplicateDifferentUser(t, upspin.EEIntegrityPack)
	})
}

func testPutDuplicateDifferentUser(t *testing.T, packing upspin.Packing) {
	const user1, user2 = "ann@example.com", "bob@example.org"
	client1 := New(setup(config.SetPacking(baseCfg, packing), user1))
	client2 := New(setup(config.SetPacking(baseCfg2, packing), user2))

	acc := "*:" + user1 + "\nread,list:" + user2
	if _, err := client1.Put(user1+"/Access", []byte(acc)); err != nil {
		t.Fatal(err)
	}

	oldName := upspin.PathName(fmt.Sprintf("%s/%s-old", user1, packing))
	text := "the rain in spain"
	if _, err := client1.Put(oldName, []byte(text)); err != nil {
		t.Fatal(err)
	}

	newName := upspin.PathName(fmt.Sprintf("%s/%s-new", user2, packing))
	if _, err := client2.PutDuplicate(oldName, newName); err != nil {
		t.Fatal(err)
	}

	got, err := client2.Get(newName)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte(text); !bytes.Equal(got, want) {
		t.Errorf("duplicate entry content is %q, want %q", got, want)
	}
}

func TestRenames(t *testing.T) {
	testRenames(t, upspin.EEPack)
	testRenames(t, upspin.EEIntegrityPack)
}

func testRenames(t *testing.T, packing upspin.Packing) {
	owner := upspin.UserName(fmt.Sprintf("owner@%d.testrenames.com", packing))
	user := upspin.UserName(fmt.Sprintf("user@%d.testrenames.com", packing))
	text := "the rain in spain"

	// Use different keys for the two users.
	cfg := config.SetPacking(baseCfg, packing)
	ownerClient := New(setup(cfg, owner))
	cfg = config.SetPacking(baseCfg2, packing)
	userClient := New(setup(cfg, user))

	// Allow user to use owner's directory.
	access := upspin.PathName(fmt.Sprintf("%s/Access", owner))
	perms := fmt.Sprintf("*: %s, %s\n", owner, user)
	if _, err := ownerClient.Put(access, []byte(perms)); err != nil {
		t.Fatal("put file:", err)
	}

	// User creates and renames.
	original := upspin.PathName(fmt.Sprintf("%s/user_original", owner))
	if _, err := userClient.Put(original, []byte(text)); err != nil {
		t.Fatal("put file:", err)
	}
	renamed := upspin.PathName(fmt.Sprintf("%s/user_renamed", owner))
	if _, err := userClient.Rename(original, renamed); err != nil {
		t.Fatal("rename file:", err)
	}

	// Owner renames user created file.
	if _, err := ownerClient.Rename(renamed, original); err != nil {
		t.Fatal("rename file:", err)
	}
	if err := ownerClient.Delete(original); err != nil {
		t.Fatal("delete file:", err)
	}

	// Owner creates and renames.
	original = upspin.PathName(fmt.Sprintf("%s/owner_original", owner))
	if _, err := userClient.Put(original, []byte(text)); err != nil {
		t.Fatal("put file:", err)
	}
	renamed = upspin.PathName(fmt.Sprintf("%s/owner_renamed", owner))
	if _, err := userClient.Rename(original, renamed); err != nil {
		t.Fatal("link file:", err)
	}

	// User renames owner created file.
	if _, err := userClient.Rename(renamed, original); err != nil {
		t.Fatal("link file:", err)
	}
	if err := userClient.Delete(original); err != nil {
		t.Fatal("delete file:", err)
	}
}

func TestSetTimes(t *testing.T) {
	testSetTimes(t, upspin.PlainPack)
	testSetTimes(t, upspin.EEPack)
	testSetTimes(t, upspin.EEIntegrityPack)
	testSetTimeSequenced(t, upspin.PlainPack)
	testSetTimeSequenced(t, upspin.EEPack)
	testSetTimeSequenced(t, upspin.EEIntegrityPack)
}

func testSetTimes(t *testing.T, packing upspin.Packing) {
	owner := upspin.UserName(fmt.Sprintf("owner@%d.testsettimes.com", packing))
	cfg := config.SetPacking(baseCfg, packing)
	client := New(setup(cfg, owner))
	text := "the rain in spain"

	// Create.
	path := upspin.PathName(fmt.Sprintf("%s/file", owner))
	oldDirEntry, err := client.Put(path, []byte(text))
	if err != nil {
		t.Fatal("put file:", err)
	}

	// Updates the time.
	if err := client.SetTime(path, oldDirEntry.Time+100); err != nil {
		t.Fatal("rename file:", err)
	}

	// Make sure it was really updated.
	newDirEntry, err := client.Lookup(path, followFinalLink)
	if err != nil {
		t.Fatal("lookup file:", err)
	}
	if newDirEntry.Time != oldDirEntry.Time+100 {
		t.Fatalf("time mismatch: got %d expected %d", newDirEntry.Time, oldDirEntry.Time+100)
	}
}

func testSetTimeSequenced(t *testing.T, packing upspin.Packing) {
	const (
		user = "user1@google.com"
		root = user + "/"
	)
	client := New(setup(baseCfg, user))
	const (
		fileName = root + "file"
		text     = "hello sailor"
	)

	// Put the initial version, remembering the sequence.
	oldDirEntry, err := client.PutSequenced(fileName, upspin.SeqIgnore, []byte(text))
	if err != nil {
		t.Fatal("put file:", err)
	}
	seq := oldDirEntry.Sequence

	// Set time using that sequence number. This should work.
	d, err := client.SetTimeSequenced(fileName, seq, oldDirEntry.Time+100)
	if err != nil {
		t.Fatal("set time sequenced file:", err)
	}
	if d.Time != oldDirEntry.Time+100 {
		t.Fatalf("time mismatch: got %d expected %d", d.Time, oldDirEntry.Time+100)
	}

	// Make sure it was really updated.
	newDirEntry, err := client.Lookup(fileName, followFinalLink)
	if err != nil {
		t.Fatal("lookup file:", err)
	}
	if newDirEntry.Sequence == seq {
		t.Fatalf("sequence number should have advanced")
	}
	if newDirEntry.Time != oldDirEntry.Time+100 {
		t.Fatalf("time mismatch: got %d expected %d", newDirEntry.Time, oldDirEntry.Time+100)
	}
}

func TestSimpleLinks(t *testing.T) {
	const (
		user     = "linker@google.com"
		root     = user + "/"
		dirName  = root + "/dir"
		fileName = dirName + "/file"
		linkName = root + "/link"
		text     = "hello sailor"
		linkText = "what a lovely day"
	)
	client := New(setup(baseCfg, user))
	// Install and check file.
	_, err := client.MakeDirectory(dirName)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Put(fileName, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	data, err := client.Get(fileName)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != text {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, text)
	}
	// Make a link.
	entry, err := client.PutLink(fileName, linkName)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("empty entry from PutLink")
	}
	// Get through the link.
	data, err = client.Get(linkName)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != text {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, text)
	}
	// Put through the link.
	_, err = client.Put(linkName, []byte(linkText))
	if err != nil {
		t.Fatal(err)
	}
	// Get through the file.
	data, err = client.Get(fileName)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != linkText {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, linkText)
	}
	// Get through the link.
	data, err = client.Get(linkName)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != linkText {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, linkText)
	}
	// Delete the link.
	err = client.Delete(linkName)
	if err != nil {
		t.Fatal(err)
	}
	// Get through the file, which should still be there.
	_, err = client.Get(fileName)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGlobLinks(t *testing.T) {
	const (
		user     = "linkglobber@google.com"
		root     = user
		dirName  = root + "/dir"
		fileName = dirName + "/file"
		linkName = root + "/link" // Will point to dir.
		text     = "ignored"
	)
	client := New(setup(baseCfg, user))
	_, err := client.MakeDirectory(dirName)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Put(fileName, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	// Link to directory.
	_, err = client.PutLink(dirName, linkName)
	if err != nil {
		t.Fatal(err)
	}

	// There are two entries in the root, one a link.
	if !globAndCheck(t, client, root+"/*",
		"linkglobber@google.com/dir", "linkglobber@google.com/link") {
		t.Error("glob failed")
	}
	if !globAndCheck(t, client, dirName+"/*",
		"linkglobber@google.com/dir/file") {
		t.Error("glob failed")
	}
	log.SetLevel("debug")
	if !globAndCheck(t, client, linkName+"/*",
		"linkglobber@google.com/dir/file") {
		t.Error("glob failed")
	}
	log.SetLevel("info")
	// There is only one file, although there are two paths to it.
	if !globAndCheck(t, client, root+"/*/*",
		"linkglobber@google.com/dir/file") {
		t.Error("glob failed")
	}
}

func TestBrokenLink(t *testing.T) {
	const (
		user     = "linkbroken@google.com"
		root     = user + "/"
		dirName  = root + "/dir"
		fileName = dirName + "/file"
		linkName = root + "/link"
		linkText = "what a lovely day"
	)
	client := New(setup(baseCfg, user))
	// Install and check file.
	_, err := client.MakeDirectory(dirName)
	if err != nil {
		t.Fatal(err)
	}
	// Make a broken link.
	entry, err := client.PutLink(fileName, linkName)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("empty entry from PutLink")
	}
	// Attempt Get through the broken link.
	_, err = client.Get(linkName)
	if !errors.Is(errors.BrokenLink, err) {
		t.Fatalf("BrokenLink error not raised for %q: %q", linkName, err)
	}
	// Put through the link.
	_, err = client.Put(linkName, []byte(linkText))
	if err != nil {
		t.Fatal(err)
	}
	// Get through the file.
	data, err := client.Get(fileName)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != linkText {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, linkText)
	}
	// Get through the link.
	data, err = client.Get(linkName)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != linkText {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, linkText)
	}
	// Delete the link.
	err = client.Delete(linkName)
	if err != nil {
		t.Fatal(err)
	}
	// Get through the file, which should still be there.
	_, err = client.Get(fileName)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRejectBadAccessFile(t *testing.T) {
	const (
		user          = "bad@access.org"
		root          = user
		accessFile    = root + "/Access"
		accessContent = "all:*"
	)
	client := New(setup(baseCfg, user))
	_, err := client.Put(accessFile, []byte(accessContent))
	expectedErr := errors.E(upspin.PathName(accessFile), errors.Invalid)
	if !errors.Match(expectedErr, err) {
		t.Fatalf("error = %s, want = %s", err, expectedErr)
	}
}

func TestRejectBadGroupFile(t *testing.T) {
	const (
		user         = "bad@group.org"
		root         = user
		groupDir     = root + "/Group"
		groupFile    = groupDir + "/mygroup"
		groupContent = "foo@x, yo! ; whoo-hoo!"
	)
	client := New(setup(baseCfg, user))
	_, err := client.MakeDirectory(groupDir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Put(groupFile, []byte(groupContent))
	expectedErr := errors.E(upspin.PathName(groupFile), errors.Invalid)
	if !errors.Match(expectedErr, err) {
		t.Fatalf("error = %s, want = %s", err, expectedErr)
	}
}

func TestAllUsers(t *testing.T) {
	const (
		user1      = "aly@example.com"
		user2      = "kim@example.org"
		accessFile = user1 + "/Access"
		file       = user1 + "/file"
	)
	var (
		cfg1    = config.SetPacking(setup(baseCfg, user1), upspin.EEPack)
		cfg2    = setup(baseCfg2, user2)
		client1 = New(cfg1)
		client2 = New(cfg2)
		packer  = pack.Lookup(cfg1.Packing())
	)

	// Allow all users to read the user's root.
	de, err := client1.Put(accessFile, []byte("r:all\n*:"+user1))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := packer.UnpackableByAll(de); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Errorf("UnpackableByAll(%q) returned false, want true", accessFile)
	}

	// Write a file and check its permissions.
	de, err = client1.Put(file, []byte("some content"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := packer.UnpackableByAll(de); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Errorf("UnpackableByAll(%q) returned false, want true", file)
	}
	_, err = client2.Get(file)
	if err != nil {
		t.Fatal(err)
	}

	// Remove all users from access file.
	de, err = client1.Put(accessFile, []byte("*:"+user1))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := packer.UnpackableByAll(de); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Errorf("UnpackableByAll(%q) returned false, want true", accessFile)
	}

	// Re-write the file and check permissions.
	de, err = client1.Put(file, []byte("more content"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := packer.UnpackableByAll(de); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Errorf("UnpackableByAll(%q) returned true, want false", file)
	}
	_, err = client2.Get(file)
	if !errors.Is(errors.Private, err) {
		t.Fatalf("Get(%q) returned %v, want Private error", file, err)
	}

	// Allow all users again, and check that client2 still can't read file
	// (it hasn't been re-wrapped yet).
	_, err = client1.Put(accessFile, []byte("r:all\n*:"+user1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client2.Get(file)
	if want := "no wrapped key for user"; err == nil {
		t.Fatalf("Get(%q) returned nil, want %q error", file, want)
	} else if got := err.Error(); !strings.Contains(got, want) {
		t.Fatalf("Get(%q) returned %v, want %q error", file, err, want)
	}
}

// TODO add a malicious directory server to test tinfoil checks

// errReader yields n bytes and then fails.
type errReader struct {
	n   int
	err error
}

func (r *errReader) Read(b []byte) (int, error) {
	if r.n <= 0 {
		return 0, r.err
	}
	if len(b) > r.n {
		b = b[:r.n]
	}
	for i := range b {
		b[i] = byte(i)
	}
	r.n -= len(b)
	return len(b), nil
}

// TestPutFromGet checks that a file stored a block at a time from a reader,
// including one delivering short reads, is stored in the same blocks as one
// stored from memory, and reads back correctly.
func TestPutFromGet(t *testing.T) {
	const (
		user     = "putfrom@example.com"
		fromName = user + "/from"
		putName  = user + "/put"
		size     = 10*1023 + 17 // Several blocks plus a partial one.
	)
	client := New(setup(baseCfg, user))

	// Use a smaller block size so the file spans many blocks.
	oldBlockSize := flags.BlockSize
	flags.BlockSize = 1023
	defer func() {
		flags.BlockSize = oldBlockSize
	}()

	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i * 7)
	}

	// HalfReader returns short reads, so blocks must be assembled from
	// several reads.
	_, err := client.PutFrom(fromName, iotest.HalfReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatal("put from reader:", err)
	}
	got, err := client.Get(fromName)
	if err != nil {
		t.Fatal("get:", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("get returned %d bytes, want %d; contents differ", len(got), len(data))
	}

	// The blocks must be laid out exactly as Put lays them out.
	if _, err := client.Put(putName, data); err != nil {
		t.Fatal("put:", err)
	}
	fromEntry, err := client.Lookup(fromName, true)
	if err != nil {
		t.Fatal(err)
	}
	putEntry, err := client.Lookup(putName, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := (size + 1022) / 1023; len(fromEntry.Blocks) != want {
		t.Fatalf("PutFrom made %d blocks, want %d", len(fromEntry.Blocks), want)
	}
	if len(fromEntry.Blocks) != len(putEntry.Blocks) {
		t.Fatalf("PutFrom made %d blocks, Put made %d", len(fromEntry.Blocks), len(putEntry.Blocks))
	}
	for i := range fromEntry.Blocks {
		f, p := fromEntry.Blocks[i], putEntry.Blocks[i]
		if f.Offset != p.Offset || f.Size != p.Size {
			t.Fatalf("block %d: PutFrom has offset %d size %d, Put has offset %d size %d",
				i, f.Offset, f.Size, p.Offset, p.Size)
		}
	}
}

func TestPutFromEmpty(t *testing.T) {
	const (
		user     = "putfromempty@example.com"
		fromName = user + "/from"
		putName  = user + "/put"
	)
	client := New(setup(baseCfg, user))
	if _, err := client.PutFrom(fromName, strings.NewReader("")); err != nil {
		t.Fatal("put from reader:", err)
	}
	if _, err := client.Put(putName, nil); err != nil {
		t.Fatal("put:", err)
	}
	for _, name := range []upspin.PathName{fromName, putName} {
		got, err := client.Get(name)
		if err != nil {
			t.Fatal("get:", err)
		}
		if len(got) != 0 {
			t.Fatalf("get of %q returned %d bytes, want 0", name, len(got))
		}
		entry, err := client.Lookup(name, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(entry.Blocks) != 0 {
			t.Fatalf("%q has %d blocks, want 0", name, len(entry.Blocks))
		}
	}
}

func TestPutSequencedFrom(t *testing.T) {
	const (
		user     = "putseqfrom@example.com"
		fileName = user + "/file"
		text     = "hello sailor"
		text2    = "put your lips together and blow"
	)
	client := New(setup(baseCfg, user))
	d, err := client.PutSequencedFrom(fileName, upspin.SeqIgnore, strings.NewReader(text))
	if err != nil {
		t.Fatal("put file:", err)
	}
	seq := d.Sequence
	// The right sequence number succeeds and advances the sequence.
	d, err = client.PutSequencedFrom(fileName, seq, strings.NewReader(text2))
	if err != nil {
		t.Fatal("put file:", err)
	}
	if d.Sequence == seq {
		t.Fatalf("sequence number should have advanced")
	}
	// The old sequence number fails and leaves the data unchanged.
	if _, err = client.PutSequencedFrom(fileName, seq, strings.NewReader(text)); err == nil {
		t.Fatalf("PutSequencedFrom with wrong sequence number should have failed")
	}
	data, err := client.Get(fileName)
	if err != nil {
		t.Fatal("get file:", err)
	}
	if string(data) != text2 {
		t.Fatalf("get of %q has text %q; should be %q", fileName, data, text2)
	}
}

// TestPutFromReadError checks that a failing reader fails the Put and
// leaves no file behind.
func TestPutFromReadError(t *testing.T) {
	const (
		user     = "putfromerr@example.com"
		fileName = user + "/file"
	)
	client := New(setup(baseCfg, user))
	oldBlockSize := flags.BlockSize
	flags.BlockSize = 1023
	defer func() {
		flags.BlockSize = oldBlockSize
	}()

	readErr := errors.Str("disk on fire")
	_, err := client.PutFrom(fileName, &errReader{n: 3000, err: readErr})
	if err == nil {
		t.Fatal("PutFrom with failing reader should have failed")
	}
	if !strings.Contains(err.Error(), readErr.Error()) {
		t.Fatalf("error = %v, want it to mention %v", err, readErr)
	}
	_, err = client.Lookup(fileName, true)
	if !errors.Is(errors.NotExist, err) {
		t.Fatalf("after failed PutFrom, Lookup error = %v, want NotExist", err)
	}
}

func TestPutFromRejectsBadAccessFile(t *testing.T) {
	const (
		user          = "badfrom@access.org"
		accessFile    = user + "/Access"
		accessContent = "all:*"
	)
	client := New(setup(baseCfg, user))
	_, err := client.PutFrom(accessFile, strings.NewReader(accessContent))
	expectedErr := errors.E(upspin.PathName(accessFile), errors.Invalid)
	if !errors.Match(expectedErr, err) {
		t.Fatalf("error = %s, want = %s", err, expectedErr)
	}
	// A valid Access file is accepted and stored in full.
	const good = "read: all\n"
	if _, err := client.PutFrom(accessFile, strings.NewReader(good)); err != nil {
		t.Fatal("put good access file:", err)
	}
	data, err := client.Get(accessFile)
	if err != nil {
		t.Fatal("get access file:", err)
	}
	if string(data) != good {
		t.Fatalf("access file has %q, want %q", data, good)
	}
}

func TestPutFromRejectsBadGroupFile(t *testing.T) {
	const (
		user         = "badfrom@group.org"
		groupDir     = user + "/Group"
		groupFile    = groupDir + "/mygroup"
		groupContent = "foo@x, yo! ; whoo-hoo!"
	)
	client := New(setup(baseCfg, user))
	if _, err := client.MakeDirectory(groupDir); err != nil {
		t.Fatal(err)
	}
	_, err := client.PutFrom(groupFile, strings.NewReader(groupContent))
	expectedErr := errors.E(upspin.PathName(groupFile), errors.Invalid)
	if !errors.Match(expectedErr, err) {
		t.Fatalf("error = %s, want = %s", err, expectedErr)
	}
}

// TestCreateLargeFile checks that a File larger than a block, and so
// larger than is held in memory, written through Create is stored
// in full and reads back correctly.
func TestCreateLargeFile(t *testing.T) {
	const (
		user     = "createlarge@example.com"
		fileName = user + "/file"
		size     = 2*upspin.BlockSize + 12345
	)
	client := New(setup(baseCfg, user))
	f, err := client.Create(fileName)
	if err != nil {
		t.Fatal("create:", err)
	}
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i * 13)
	}
	// Write in odd-sized pieces, then go back and change the start.
	const piece = 100000
	for off := 0; off < size; off += piece {
		end := off + piece
		if end > size {
			end = size
		}
		if _, err := f.Write(data[off:end]); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
	}
	copy(data[10:20], "0123456789")
	if _, err := f.WriteAt(data[10:20], 10); err != nil {
		t.Fatal("writeAt:", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal("close:", err)
	}

	got, err := client.Get(fileName)
	if err != nil {
		t.Fatal("get:", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("get returned %d bytes, want %d; contents differ", len(got), len(data))
	}
	entry, err := client.Lookup(fileName, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.Blocks) != 3 {
		t.Fatalf("file has %d blocks, want 3", len(entry.Blocks))
	}
}

// TestRequirePacking checks the downgrade defense: with requirepacking
// set to eepq, the client refuses an ee entry that the directory server
// serves (Get and Open) and refuses to write under ee (Put), while the
// same entry is readable when the config requires ee, and Access files
// are exempt.
func TestRequirePacking(t *testing.T) {
	const (
		user = upspin.UserName("require@example.com")
		text = "written under ee before the requirement"
	)
	cfg := setup(config.SetPacking(baseCfg, upspin.EEPack), user)
	client := New(cfg)
	name := upspin.PathName(user + "/file")
	if _, err := client.Put(name, []byte(text)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Put(upspin.PathName(user+"/Access"), []byte("*: "+string(user)+"\n")); err != nil {
		t.Fatal(err)
	}

	// The directory server now serves an ee entry; a client that requires
	// eepq refuses it on every read path and refuses to write under ee.
	strict := New(config.SetValue(cfg, clientutil.RequiredPackingKey, "eepq"))
	if _, err := strict.Get(name); !errors.Is(errors.Permission, err) {
		t.Errorf("Get of an ee entry with requirepacking eepq: got %v, want Permission", err)
	}
	if _, err := strict.Open(name); !errors.Is(errors.Permission, err) {
		t.Errorf("Open of an ee entry with requirepacking eepq: got %v, want Permission", err)
	}
	if _, err := strict.Put(upspin.PathName(user+"/file2"), []byte("new")); !errors.Is(errors.Permission, err) {
		t.Errorf("Put under ee with requirepacking eepq: got %v, want Permission", err)
	}
	// Access files are exempt, so access checks keep working.
	if _, err := strict.Get(upspin.PathName(user + "/Access")); err != nil {
		t.Errorf("Get of the Access file with requirepacking eepq: %v", err)
	}

	// A requirement the entry meets changes nothing.
	lenient := New(config.SetValue(cfg, clientutil.RequiredPackingKey, "ee"))
	got, err := lenient.Get(name)
	if err != nil {
		t.Fatalf("Get with requirepacking ee: %v", err)
	}
	if string(got) != text {
		t.Errorf("Get with requirepacking ee: got %q, want %q", got, text)
	}

	// A requirement that names no packing fails closed.
	typo := New(config.SetValue(cfg, clientutil.RequiredPackingKey, "eepqq"))
	if _, err := typo.Get(name); !errors.Is(errors.Invalid, err) {
		t.Errorf("Get with a misspelled requirepacking: got %v, want Invalid", err)
	}
}
