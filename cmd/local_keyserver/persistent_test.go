package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"upspin.io/key/inprocess"
	"upspin.io/upspin"
)

func TestPersistentServer(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local_keyserver_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	jsonFile := filepath.Join(tmpDir, "initial.json")
	outFile := filepath.Join(tmpDir, "out.json")

	initialData := inprocess.KeyData{
		Users: []upspin.User{
			{Name: "user1@example.com"},
		},
	}
	data, _ := json.Marshal(initialData)
	os.WriteFile(jsonFile, data, 0600)

	// Create a new inprocess server
	f, _ := os.Open(jsonFile)
	key, err := inprocess.NewRW(f, false)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	ps := &persistentServer{
		KeyServer: key,
		file:      outFile,
	}

	newUser := &upspin.User{Name: "user2@example.com"}
	if err := ps.Put(newUser); err != nil {
		t.Fatal(err)
	}

	// Check if outFile exists and contains both users
	outData, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}

	var savedData inprocess.KeyData
	if err := json.Unmarshal(outData, &savedData); err != nil {
		t.Fatal(err)
	}

	if len(savedData.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(savedData.Users))
	}

	// Verify user1 still exists in memory
	u, err := ps.Lookup("user1@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "user1@example.com" {
		t.Errorf("expected user1@example.com, got %s", u.Name)
	}
}
