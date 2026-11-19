// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package killtest kills the server process of a supervised upspinfs mount
// in the middle of reads and writes, and checks that the mount keeps
// answering. It needs /dev/fuse and fusermount, starts real Upspin servers,
// and is tagged manual: run it by hand, not in CI.
package killtest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"upspin.io/upbox"
)

const (
	user   = "ann@example.com"
	schema = `
users:
  - name: ann@example.com
servers:
  - name: keyserver
  - name: storeserver
  - name: dirserver
    flags:
      kind: server
domain: example.com
`
	// opTimeout bounds every file operation. An operation that takes
	// longer is a request the kernel waits for forever.
	opTimeout = 60 * time.Second
)

// mount runs upspinfs -supervise and returns the supervisor process and the
// user's root in the mount.
type mount struct {
	t          *testing.T
	dir        string
	root       string
	supervisor *exec.Cmd
	exited     chan error
	schema     *upbox.Schema
}

func upspinfsBinary(t *testing.T) string {
	t.Helper()
	ws := os.Getenv("TEST_WORKSPACE")
	if ws == "" {
		ws = "_main"
	}
	p := filepath.Join(os.Getenv("TEST_SRCDIR"), ws, "cmd", "upspinfs", "upspinfs_", "upspinfs")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("no upspinfs binary (run under Bazel): %v", err)
	}
	return p
}

func startMount(t *testing.T, flags ...string) *mount {
	t.Helper()
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("no FUSE device: %v", err)
	}
	if _, err := exec.LookPath("fusermount"); err != nil {
		t.Skipf("no fusermount: %v", err)
	}
	sc, err := upbox.SchemaFromYAML(schema)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.Start(); err != nil {
		t.Fatalf("starting the Upspin servers: %v", err)
	}
	t.Cleanup(func() { sc.Stop() })

	m := &mount{t: t, dir: t.TempDir(), exited: make(chan error, 1), schema: sc}
	m.root = filepath.Join(m.dir, user)
	args := append([]string{"-supervise", "-config=" + sc.Config(user), "-cachedir=" + t.TempDir(), "-log=info"}, flags...)
	m.supervisor = exec.Command(upspinfsBinary(t), append(args, m.dir)...)
	m.supervisor.Stdout, m.supervisor.Stderr = os.Stdout, os.Stderr
	if err := m.supervisor.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { m.exited <- m.supervisor.Wait() }()
	t.Cleanup(m.stop)

	// The mount is ready when it is listed and a lookup of the user's
	// root gets an answer. Before the mount, a mkdir would succeed on the
	// directory below it.
	deadline := time.Now().Add(opTimeout)
	for {
		if isMounted(m.dir) {
			err := within(t, "mkdir of the user's root", func() error { return os.Mkdir(m.root, 0o700) })
			if err == nil || errors.Is(err, os.ErrExist) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the mount did not come up")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return m
}

// stop asks the supervisor to unmount and checks that it did.
func (m *mount) stop() {
	m.supervisor.Process.Signal(syscall.SIGTERM)
	select {
	case <-m.exited:
	case <-time.After(opTimeout):
		m.t.Error("the supervisor did not stop")
		m.supervisor.Process.Kill()
		<-m.exited
	}
	if isMounted(m.dir) {
		m.t.Error("the supervisor left the mount behind")
		exec.Command("fusermount", "-u", "-z", m.dir).Run()
	}
}

func isMounted(dir string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 4 && f[4] == dir {
			return true
		}
	}
	return false
}

// server returns the PID of the server process the supervisor runs, waiting
// until there is one other than not.
func (m *mount) server(not int) int {
	m.t.Helper()
	pid := m.supervisor.Process.Pid
	deadline := time.Now().Add(opTimeout)
	for time.Now().Before(deadline) {
		for _, child := range children(pid) {
			if child != not && isServer(child) {
				return child
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	var seen []string
	for _, child := range children(pid) {
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", child))
		seen = append(seen, fmt.Sprintf("%d: %q", child, bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '})))
	}
	m.t.Fatalf("the supervisor %d runs no server process other than %d; its children: %v", pid, not, seen)
	return 0
}

// children returns the PIDs of the processes whose parent is pid.
func children(pid int) []int {
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	var out []int
	for _, st := range stats {
		data, err := os.ReadFile(st)
		if err != nil {
			continue
		}
		// The fields after the command name, which ends with ')', are
		// the state and then the parent PID.
		i := bytes.LastIndexByte(data, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(data[i+1:]))
		if len(f) < 2 || f[1] != strconv.Itoa(pid) {
			continue
		}
		if child, err := strconv.Atoi(filepath.Base(filepath.Dir(st))); err == nil {
			out = append(out, child)
		}
	}
	return out
}

// isServer reports whether pid is a server process of the supervisor, not a
// probe. A process that just exited has no command line and is no server.
func isServer(pid int) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return err == nil && bytes.Contains(cmdline, []byte("-fuse_fd="))
}

// kill kills the server process and waits for its successor.
func (m *mount) kill() {
	m.t.Helper()
	old := m.server(0)
	if err := syscall.Kill(old, syscall.SIGKILL); err != nil {
		m.t.Fatal(err)
	}
	m.server(old)
}

// within2 is within for operations that also return a count.
func within2(t *testing.T, what string, op func() (int, error)) (int, error) {
	t.Helper()
	var n int
	err := within(t, what, func() error {
		var err error
		n, err = op()
		return err
	})
	return n, err
}

// within runs op and fails the test if it does not return in opTimeout.
func within(t *testing.T, what string, op func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		return err
	case <-time.After(opTimeout):
		t.Fatalf("%s did not return in %v: the request was lost", what, opTimeout)
		return nil
	}
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// TestKillDuringRead reads a file through one descriptor across a kill.
func TestKillDuringRead(t *testing.T) {
	m := startMount(t)
	name := filepath.Join(m.root, "read")
	want := pattern(1 << 20)
	if err := within(t, "write", func() error { return os.WriteFile(name, want, 0o600) }); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := make([]byte, len(want))
	if _, err := f.ReadAt(got[:100000], 0); err != nil {
		t.Fatal(err)
	}
	m.kill()
	if _, err := within2(t, "read after the kill", func() (int, error) { return f.ReadAt(got[100000:500000], 100000) }); err != nil {
		t.Fatalf("read through a descriptor opened before the kill: %v", err)
	}
	// A second kill, of the server that took over.
	m.kill()
	err = within(t, "read after the second kill", func() error {
		_, err := f.ReadAt(got[500000:], 500000)
		return err
	})
	if err != nil {
		t.Fatalf("read through a descriptor opened before the kill: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("read different data after the kill")
	}
}

// TestKillDuringWrite writes a file through one descriptor across a kill.
// The writes before the kill were not put; the new server must put them.
func TestKillDuringWrite(t *testing.T) {
	m := startMount(t)
	name := filepath.Join(m.root, "write")
	want := pattern(300000)
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(want[:100000]); err != nil {
		t.Fatal(err)
	}
	m.kill()
	err = within(t, "write after the kill", func() error {
		_, err := f.Write(want[100000:])
		return err
	})
	if err != nil {
		t.Fatalf("write through a descriptor opened before the kill: %v", err)
	}
	if err := within(t, "close", f.Close); err != nil {
		t.Fatalf("close after the kill: %v", err)
	}
	var got []byte
	within(t, "read back", func() error {
		got, err = os.ReadFile(name)
		return err
	})
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("file after the kill: %d bytes, %v; want %d bytes", len(got), err, len(want))
	}
}

// TestKillDuringRequests kills the server while other goroutines keep
// sending requests. Requests that the dead server had read may fail with
// EIO, but none may hang, and the mount must answer afterwards.
func TestKillDuringRequests(t *testing.T) {
	m := startMount(t)
	name := filepath.Join(m.root, "busy")
	if err := within(t, "write", func() error { return os.WriteFile(name, pattern(1<<20), 0o600) }); err != nil {
		t.Fatal(err)
	}
	stop := make(chan bool)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			var failed error
			for {
				select {
				case <-stop:
					errs <- failed
					return
				default:
				}
				done := make(chan error, 1)
				go func() {
					_, err := os.ReadFile(name)
					if err == nil {
						_, err = os.Stat(m.root)
					}
					done <- err
				}()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, syscall.EIO) {
						failed = err
					}
				case <-time.After(opTimeout):
					errs <- errors.New("a request hung across the kill")
					<-stop
					return
				}
			}
		}()
	}
	time.Sleep(time.Second)
	m.kill()
	time.Sleep(2 * time.Second)
	close(stop)
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if err := within(t, "stat after the kill", func() error { _, err := os.Stat(name); return err }); err != nil {
		t.Errorf("the mount does not answer after the kill: %v", err)
	}
}

// TestHungServerRestarts stops the server process with SIGSTOP, so that it
// lives but answers nothing. With -hang_timeout the supervisor must notice,
// kill it, and start a new one.
func TestHungServerRestarts(t *testing.T) {
	m := startMount(t, "-hang_timeout=5s")
	name := filepath.Join(m.root, "hung")
	if err := within(t, "write", func() error { return os.WriteFile(name, []byte("still here"), 0o600) }); err != nil {
		t.Fatal(err)
	}
	old := m.server(0)
	if err := syscall.Kill(old, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	var got []byte
	err := within(t, "read from a hung server", func() error {
		var err error
		got, err = os.ReadFile(name)
		return err
	})
	if err != nil && !errors.Is(err, syscall.EIO) {
		t.Fatalf("read while the server hung: %v", err)
	}
	if next := m.server(old); next == old {
		t.Fatal("the hung server was not replaced")
	}
	if err := within(t, "read after the restart", func() error {
		var err error
		got, err = os.ReadFile(name)
		return err
	}); err != nil || string(got) != "still here" {
		t.Errorf("read after the restart: %q, %v", got, err)
	}
}

// TestKillWithoutClose writes a file and kills the server before the file is
// closed. The descriptor is never closed, so no release comes: the new
// server must put the writes by itself.
func TestKillWithoutClose(t *testing.T) {
	m := startMount(t)
	name := filepath.Join(m.root, "unclosed")
	want := pattern(50000)
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(want); err != nil {
		t.Fatal(err)
	}
	m.kill()
	// Read the store with the upspin command, around the mount.
	deadline := time.Now().Add(opTimeout)
	for {
		out, err := exec.Command(m.schema.Command("upspin"), "-config="+m.schema.Config(user), "get", user+"/unclosed").Output()
		if err == nil && bytes.Equal(out, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the store does not have the writes made before the kill: %d bytes, %v", len(out), err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
