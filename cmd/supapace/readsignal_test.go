package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestCLI_ReadsKeepDefaultSignals: a read waiting for its answer is ended by
// SIGINT like any program (no handler, no message, nothing on stdout).
func TestCLI_ReadsKeepDefaultSignals(t *testing.T) {
	if sock := os.Getenv("SUPAPACE_TEST_READ_SOCK"); sock != "" {
		os.Exit(run([]string{"project", "list"}, client{sock: sock}, os.Stdout, os.Stderr))
	}
	f := newFake(t, reply{})
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLI_ReadsKeepDefaultSignals$")
	cmd.Env = append(os.Environ(), "SUPAPACE_TEST_READ_SOCK="+f.sock)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for len(f.requests()) < 1 {
		time.Sleep(time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGINT)
	err := cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child: %v", err)
	}
	ws := ee.Sys().(syscall.WaitStatus)
	if !ws.Signaled() || ws.Signal() != syscall.SIGINT || o.Len() != 0 || e.Len() != 0 {
		t.Fatalf("child: %v, stdout %q stderr %q", err, o.String(), e.String())
	}
}
