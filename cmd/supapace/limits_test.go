package main

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/pgconf"
)

// TestCLI_UsageQuotesTheLimits: the usage text names every allow-listed
// setting and the same limits the admin API enforces (pinned there by
// TestAPI_KeyBoundsMatchMessage).
func TestCLI_UsageQuotesTheLimits(t *testing.T) {
	u := usageText()
	for _, g := range pgconf.GUCAllowList {
		if !strings.Contains(u, g) {
			t.Errorf("usage lacks setting %q", g)
		}
	}
	for _, s := range []string{"1 to 16 RSA", "2048 to 4096 bits", "at least 1g", "at most 16t", "starting with a letter or digit", "default 8g", "20 characters of a-z and 0-9"} {
		if !strings.Contains(strings.Join(strings.Fields(u), " "), s) {
			t.Errorf("usage lacks %q", s)
		}
	}
	for _, line := range strings.Split(u, "\n") {
		if len(line) > 80 {
			t.Errorf("usage line over 80 columns: %q", line)
		}
	}
}

// TestCLI_TerminateWhilePolling: SIGTERM is handled like an interrupt.
func TestCLI_TerminateWhilePolling(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, running})
	var o, e bytes.Buffer
	done := make(chan int)
	go func() {
		done <- run([]string{"project", "delete", "abcdefghij0123456789"},
			client{sock: f.sock, poll: 5 * time.Millisecond, outage: time.Minute}, &o, &e)
	}()
	for len(f.requests()) < 3 {
		time.Sleep(time.Millisecond)
	}
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case code := <-done:
		if code != 130 || o.String() != running || !strings.Contains(e.String(), "supapace op show 12") {
			t.Fatalf("exit %d stdout %q stderr %q", code, o.String(), e.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no exit after SIGTERM")
	}
}
