// SPDX-License-Identifier: Apache-2.0

package main // import "upspin.io/cmd/upspinfs"

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"upspin.io/log"
	"upspin.io/shutdown"
	"upspin.io/third_party/fuse"
	"upspin.io/upspin"
)

const (
	// childFuseFD and childJournalFD are the descriptors a child upspinfs
	// gets from the supervisor: exec.Cmd.ExtraFiles start at 3.
	childFuseFD    = 3
	childJournalFD = 4

	// Restart delays. A child that ran for stableRun resets the delay.
	minRestartDelay = time.Second
	maxRestartDelay = 30 * time.Second
	stableRun       = time.Minute

	// stopTimeout is how long a stopping child gets before it is killed.
	stopTimeout = 10 * time.Second
)

// supervise mounts the file system and runs upspinfs as a child process
// that serves it. The supervisor keeps the /dev/fuse descriptor, so the
// mount lives when the child dies, and starts a new child that adopts it.
// It also keeps the journal of the FUSE tables, in a memory file, so the new
// child can restore them. It returns the exit code of the program.
//
// If hangTimeout is positive, the supervisor also restarts a server that
// stops answering: see watch.
func supervise(cfg upspin.Config, mountpoint string, allowOther bool, hangTimeout time.Duration, args []string) int {
	c, err := fuse.Mount(mountpoint, mountOptions(cfg, allowOther)...)
	if err != nil {
		log.Error.Printf("upspinfs: mount: %v", err)
		return 1
	}
	<-c.Ready
	if err := c.MountError; err != nil {
		log.Error.Printf("upspinfs: mount: %v", err)
		return 1
	}
	defer c.Close()
	conn, err := connectionID(mountpoint)
	if err != nil {
		log.Error.Printf("upspinfs: finding the FUSE connection in %s: %v", fuseConnections, err)
		if hangTimeout > 0 {
			log.Error.Printf("upspinfs: -hang_timeout is off: it needs the FUSE connection")
		}
	}

	files := []*os.File{c.File()}
	journal, err := memFile("upspinfs-journal")
	if err != nil {
		// The mount still survives a crash, but open files and
		// unsaved writes do not.
		log.Error.Printf("upspinfs: no journal, restarts lose open files: %v", err)
	} else {
		defer journal.Close()
		files = append(files, journal)
	}
	childArgs := append(childFlags(c.Protocol(), journal != nil), args...)

	self, err := os.Executable()
	if err != nil {
		log.Error.Printf("upspinfs: %v", err)
		fuse.Unmount(mountpoint)
		return 1
	}
	// The shutdown package handles SIGTERM and SIGINT: it runs the
	// registered functions and then exits. The supervisor's function asks
	// the loop below to stop the server and unmount, and waits for that.
	stop := make(chan bool, 1)
	stopped := make(chan bool)
	shutdown.Handle(func() {
		stop <- true
		<-stopped
	})
	delay := minRestartDelay
	for {
		cmd := exec.Command(self, childArgs...) // #nosec G204 G702 -- this program, with its own arguments.
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, os.Stdout, os.Stderr
		cmd.ExtraFiles = files
		// The server must not outlive the supervisor.
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		start := time.Now()
		if err := cmd.Start(); err != nil {
			log.Error.Printf("upspinfs: starting the server: %v", err)
		} else {
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			// upspinfs answers a lookup of a name starting with "._"
			// at the top of the mount from memory, and the kernel
			// does not cache the "no such file" answer, so every
			// probe reaches the server and needs no network.
			root := filepath.Join(mountpoint, "._upspinfs-probe")
			probe(self, root)
			hung := make(chan bool, 1)
			stopWatch := make(chan bool)
			if hangTimeout > 0 && conn != "" {
				go watch(self, root, conn, hangTimeout, hung, stopWatch)
			}
			select {
			case <-stop:
				log.Info.Printf("upspinfs: stopping, unmounting")
				close(stopWatch)
				stopChild(cmd, exited, conn)
				unmount(mountpoint)
				close(stopped)
				return 0
			case err := <-exited:
				if err == nil {
					// The server returns only when the mount
					// is gone, as after fusermount -u.
					log.Info.Printf("upspinfs: the server exited, the mount ended")
					unmount(mountpoint)
					return 0
				}
				log.Error.Printf("upspinfs: the server died: %v; restarting", err)
			case <-hung:
				log.Error.Printf("upspinfs: the server stopped answering for %v; restarting it", hangTimeout)
				close(stopWatch)
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(stopTimeout):
					// It waits for its own mount and cannot die.
					// Only aborting the connection frees it, and
					// that ends the mount.
					log.Error.Printf("upspinfs: the hung server does not die; giving up the mount")
					stopChild(cmd, exited, conn)
					unmount(mountpoint)
					return 1
				}
				continue
			}
			close(stopWatch)
		}
		if time.Since(start) > stableRun {
			delay = minRestartDelay
		}
		select {
		case <-stop:
			log.Info.Printf("upspinfs: stopping, unmounting")
			unmount(mountpoint)
			close(stopped)
			return 0
		case <-time.After(delay):
		}
		if delay *= 2; delay > maxRestartDelay {
			delay = maxRestartDelay
		}
	}
}

// childFlags returns the flags that make a child adopt the supervisor's
// descriptors.
func childFlags(proto fuse.Protocol, journal bool) []string {
	flags := []string{
		// The child runs the same program, where -supervise is the
		// default.
		"-supervise=false",
		fmt.Sprintf("-fuse_fd=%d", childFuseFD),
		fmt.Sprintf("-fuse_proto=%d.%d", proto.Major, proto.Minor),
	}
	if journal {
		flags = append(flags, fmt.Sprintf("-journal_fd=%d", childJournalFD))
	}
	return flags
}

// stopChild asks the child to stop, and kills it if it does not. A process
// that waits for an answer from its own mount cannot die even of SIGKILL, so
// as a last resort stopChild aborts the FUSE connection conn, which fails
// every request on it. The mount is being torn down anyway.
func stopChild(cmd *exec.Cmd, exited chan error, conn string) {
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return
	}
	select {
	case <-exited:
		return
	case <-time.After(stopTimeout):
	}
	cmd.Process.Kill()
	select {
	case <-exited:
		return
	case <-time.After(stopTimeout):
	}
	if conn == "" {
		log.Error.Printf("upspinfs: the server does not die, and the FUSE connection is unknown")
		return
	}
	log.Error.Printf("upspinfs: the server does not die; aborting FUSE connection %s", conn)
	if err := os.WriteFile(filepath.Join(fuseConnections, conn, "abort"), []byte("1"), 0); err != nil {
		log.Error.Printf("upspinfs: aborting the FUSE connection: %v", err)
		return
	}
	<-exited
}

// watch reports on hung when the server stops answering: a lookup of root, a
// name the server answers from memory, gets no answer in timeout while the
// kernel has requests waiting. A slow store does not delay that answer, and
// the waiting count rules out a probe that failed to start. It returns when
// stop is closed or after reporting.
func watch(self, root, conn string, timeout time.Duration, hung chan<- bool, stop <-chan bool) {
	interval := timeout / 2
	if interval < time.Second {
		interval = time.Second
	}
	// A new server may take a while to start: give it one timeout.
	select {
	case <-stop:
		return
	case <-time.After(timeout):
	}
	for {
		select {
		case <-stop:
			return
		case <-time.After(interval):
		}
		answered := make(chan bool, 1)
		cmd := exec.Command(self, "-fuse_probe="+root) // #nosec G204 G702 -- this program.
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			continue
		}
		go func() { cmd.Wait(); answered <- true }()
		select {
		case <-stop:
			return
		case <-answered:
			continue
		case <-time.After(timeout):
		}
		waiting, err := os.ReadFile(filepath.Join(fuseConnections, conn, "waiting"))
		if err == nil && strings.TrimSpace(string(waiting)) != "0" {
			hung <- true
			return
		}
		// The probe is slow for another reason; do not let them pile up.
		cmd.Process.Kill()
	}
}

// unmount unmounts mountpoint. If the mount is busy, as when a process still
// waits in it, it detaches the mount: the kernel removes it when the last
// user is gone.
func unmount(mountpoint string) {
	if err := fuse.Unmount(mountpoint); err == nil {
		return
	}
	if out, err := exec.Command("fusermount", "-u", "-z", mountpoint).CombinedOutput(); err != nil {
		log.Error.Printf("upspinfs: unmounting %s: %v: %s", mountpoint, err, out)
	}
}

// fuseConnections is where the kernel's fusectl file system lists the FUSE
// connections. Each one is a directory named after the minor device number
// of its mount.
const fuseConnections = "/sys/fs/fuse/connections"

// connectionID returns the name of the fusectl directory of the mount at
// mountpoint. It reads /proc/self/mountinfo: a stat of the mountpoint would
// be a FUSE request, which no server may be there to answer.
func connectionID(mountpoint string) (string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	// mountinfo lists the path with its symbolic links resolved. Only the
	// parent is resolved here: any look at the mountpoint itself is a FUSE
	// request.
	if dir, err := filepath.EvalSymlinks(filepath.Dir(mountpoint)); err == nil {
		mountpoint = filepath.Join(dir, filepath.Base(mountpoint))
	}
	id := mountMinor(string(data), mountpoint)
	if id == "" {
		return "", errors.New("no mount at " + mountpoint)
	}
	if _, err := os.Stat(filepath.Join(fuseConnections, id)); err != nil { // #nosec G703 -- id is a device number from mountinfo.
		return "", err
	}
	return id, nil
}

// mountMinor returns the minor device number of the mount at mountpoint in
// the mountinfo text, or "" if there is none. A later line is a mount on top
// of an earlier one.
func mountMinor(mountinfo, mountpoint string) string {
	id := ""
	for _, line := range strings.Split(mountinfo, "\n") {
		// Fields: mount ID, parent ID, major:minor, root, mount point.
		f := strings.Fields(line)
		if len(f) > 4 && unescapeMountinfo(f[4]) == mountpoint {
			if _, minor, ok := strings.Cut(f[2], ":"); ok {
				id = minor
			}
		}
	}
	return id
}

// unescapeMountinfo undoes the octal escapes (\040 for a space) that the
// kernel writes into mountinfo paths.
func unescapeMountinfo(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// probe looks up path in a separate process, without waiting for it. A new
// server learns from its first request which requests the dead one lost, and
// the lookup makes that first request. The server itself must not look into
// its own mount: a process that waits for its own answer cannot exit.
func probe(self, path string) {
	cmd := exec.Command(self, "-fuse_probe="+path) // #nosec G204 G702 -- this program.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		log.Error.Printf("upspinfs: probing the mount: %v", err)
		return
	}
	go cmd.Wait()
}

// memFile returns a new file that lives only in memory (memfd_create).
func memFile(name string) (*os.File, error) {
	const mfdCloexec = 1
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	if !memfdKnown {
		return nil, errors.New("memfd_create: unknown on this architecture")
	}
	fd, _, errno := syscall.Syscall(uintptr(sysMemfdCreate), uintptr(unsafe.Pointer(p)), mfdCloexec, 0)
	if errno != 0 {
		return nil, errors.New("memfd_create: " + errno.Error())
	}
	return os.NewFile(fd, name), nil
}
