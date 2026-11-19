package fuse

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

func newOSXFUSEcallMount(bin string, daemonVar string, dir string, conf *mountConfig, ready chan<- struct{}, errp *error) (*os.File, error) {
	for k, v := range conf.options {
		if strings.Contains(k, ",") || strings.Contains(v, ",") {
			// Silly limitation but the mount helper does not
			// understand any escaping. See TestMountOptionCommaError.
			return nil, fmt.Errorf("mount options cannot contain commas on darwin: %q=%q", k, v)
		}
	}

	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %v", err)
	}

	writeFile := os.NewFile(uintptr(fds[0]), "fusermount-child-writes")
	defer writeFile.Close()

	readFile := os.NewFile(uintptr(fds[1]), "fusermount-parent-reads")
	defer readFile.Close()

	cmd := exec.Command(
		bin,
		"-o", conf.getOptions(),
		// Tell osxfuse-kext how large our buffer is. It must split
		// writes larger than this into multiple writes.
		//
		// OSXFUSE seems to ignore InitResponse.MaxWrite, and uses
		// this instead.
		"-o", "iosize="+strconv.FormatUint(maxWrite, 10),
		"--",
		dir,
	)
	cmd.ExtraFiles = []*os.File{writeFile}
	cmd.Env = append(os.Environ(), "_FUSE_COMMFD=3")
	// OSXFUSE <3.3.0
	cmd.Env = append(cmd.Env, "MOUNT_FUSEFS_CALL_BY_LIB=")
	// OSXFUSE >=3.3.0
	cmd.Env = append(cmd.Env, "MOUNT_OSXFUSE_CALL_BY_LIB=")
	// OSXFUSE >=4.0.0
	cmd.Env = append(cmd.Env, "_FUSE_CALL_BY_LIB=")

	daemon := os.Args[0]
	if daemonVar != "" {
		cmd.Env = append(cmd.Env, daemonVar+"="+daemon)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("setting up mount_osxfusefs stderr: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("setting up mount_osxfusefs stderr: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mount_osxfusefs: %v", err)
	}
	helperErrCh := make(chan error, 1)
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go lineLogger(&wg, "mount helper output", neverIgnoreLine, stdout)
		helperName := path.Base(bin)
		go lineLogger(&wg, "mount helper error", handleMountOSXFUSE(helperName, helperErrCh), stderr)
		wg.Wait()
		if err := cmd.Wait(); err != nil {
			// see if we have a better error to report
			select {
			case helperErr := <-helperErrCh:
				// log the Wait error if it's not what we expected
				if !isBoringMountOSXFUSEError(err) {
					log.Printf("mount helper failed: %v", err)
				}
				// and now return what we grabbed from stderr as the real
				// error
				*errp = helperErr
				close(ready)
				return
			default:
				// nope, fall back to generic message
			}

			*errp = fmt.Errorf("mount_osxfusefs: %v", err)
			close(ready)
			return
		}

		*errp = nil
		close(ready)
	}()

	c, err := net.FileConn(readFile)
	if err != nil {
		return nil, fmt.Errorf("FileConn from fusermount socket: %v", err)
	}
	defer c.Close()

	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("unexpected FileConn type; expected UnixConn, got %T", c)
	}

	buf := make([]byte, 32) // expect 1 byte
	oob := make([]byte, 32) // expect 24 bytes
	_, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("ParseSocketControlMessage: %v", err)
	}
	if len(scms) != 1 {
		return nil, fmt.Errorf("expected 1 SocketControlMessage; got scms = %#v", scms)
	}
	scm := scms[0]
	gotFds, err := syscall.ParseUnixRights(&scm)
	if err != nil {
		return nil, fmt.Errorf("syscall.ParseUnixRights: %v", err)
	}
	if len(gotFds) != 1 {
		return nil, fmt.Errorf("wanted 1 fd; got %#v", gotFds)
	}
	f := os.NewFile(uintptr(gotFds[0]), "/dev/fuse")
	return f, nil
}

func newOSXFUSEmount(dir string, conf *mountConfig, ready chan<- struct{}, errp *error) (*os.File, error) {
	locations := conf.osxfuseLocations
	if locations == nil {
		locations = []OSXFUSEPaths{
			OSXFUSELocationV4,
			OSXFUSELocationV3,
			OSXFUSELocationV2,
		}
	}
	for _, loc := range locations {
		if _, err := os.Stat(loc.Mount); os.IsNotExist(err) {
			// try the other locations
			continue
		}

		f, err := newOSXFUSEcallMount(loc.Mount, loc.DaemonVar, dir, conf, ready, errp)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	return nil, ErrOSXFUSENotFound
}
