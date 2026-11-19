package fuse

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

var (
	errNoAvail   = errors.New("no available fuse devices")
	errNotLoaded = errors.New("osxfuse is not loaded")
)

func handleMountOSXFUSE(helperName string, errCh chan<- error) func(line string) (ignore bool) {
	var noMountpointPrefix = helperName + `: `
	const noMountpointSuffix = `: No such file or directory`
	return func(line string) (ignore bool) {
		if strings.HasPrefix(line, noMountpointPrefix) && strings.HasSuffix(line, noMountpointSuffix) {
			// re-extract it from the error message in case some layer
			// changed the path
			mountpoint := line[len(noMountpointPrefix) : len(line)-len(noMountpointSuffix)]
			err := &MountpointDoesNotExistError{
				Path: mountpoint,
			}
			select {
			case errCh <- err:
				return true
			default:
				// not the first error; fall back to logging it
				return false
			}
		}

		return false
	}
}

// isBoringMountOSXFUSEError returns whether the Wait error is
// uninteresting; exit status 64 is.
func isBoringMountOSXFUSEError(err error) bool {
	if err, ok := err.(*exec.ExitError); ok && err.Exited() {
		if status, ok := err.Sys().(syscall.WaitStatus); ok && status.ExitStatus() == 64 {
			return true
		}
	}
	return false
}

// Before BigSur, fuse was a pseudo-device one opened. After it became a socket type.
func mount(dir string, conf *mountConfig, ready chan<- struct{}, errp *error) (*os.File, error) {
	version, err := osxversion()
	if err != nil {
		version = "10.1.1"
	}
	components := strings.Split(version, ".")
	major, err := strconv.ParseUint(components[0], 10, 64)
	if err != nil || major < 11 {
		return oldOSXFUSEmount(dir, conf, ready, errp)
	}
	return newOSXFUSEmount(dir, conf, ready, errp)	
}

// Different apple os versions have different programmatical ways to get the verion but
// sysctl command seems to work across them.  Thank you BSD.
func osxversion() (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command("sysctl", "kern.osproductversion")
	cmd.Stdout = &buf
	err := cmd.Run()
	if err != nil {
		return "???", err
	}
	lines := strings.Split(buf.String(), "\n")
	for _, line := range lines {
		words := strings.Split(line, " ")
		if len(words) > 1 && words[0] == "kern.osproductversion:" {
			return words[1], nil
			break
		}
	}
	return "???", fmt.Errorf("can't determine version")
}

// Different mount helpers use different names for this mount option.
func subtypeOptionName() string {
	return "fssubtype"
}
