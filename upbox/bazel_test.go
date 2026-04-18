package upbox

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestFindBinaries(t *testing.T) {
	testSrcDir := os.Getenv("TEST_SRCDIR")
	if testSrcDir == "" {
		t.Skip("Not running under Bazel")
	}
	fmt.Printf("TEST_SRCDIR: %s\n", testSrcDir)
	filepath.Walk(testSrcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (filepath.Base(path) == "upspin" || filepath.Base(path) == "cacheserver") {
			fmt.Printf("Found: %s\n", path)
		}
		return nil
	})
}
