package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// A display that failed is no display: nothing is acknowledged.
func TestEscrowAck_ADisplayThatFailsIsNotAcknowledged(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	// A file closed before the command writes: every write fails.
	shut, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	shut.Close()
	var errb bytes.Buffer
	oldOut, oldErr := stdout, stderr
	stdout, stderr = shut, &errb
	code := run([]string{"escrow", "ack"})
	stdout, stderr = oldOut, oldErr
	if code != 1 || !strings.Contains(errb.String(), "could not be shown") || e.acked() != "" {
		t.Fatalf("exit %d, %q, acknowledged %q", code, errb.String(), e.acked())
	}
	for name, s := range e.secretTexts() {
		if strings.Contains(errb.String(), s) {
			t.Fatalf("the refusal shows %s", name)
		}
	}
}

// The escrow commands open the control-plane database only in an environment
// the client library reads nothing from.
func TestEscrow_RefusesClientLibrarySettingsInTheEnvironment(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	t.Setenv("PGOPTIONS", "-c statement_timeout=1")
	for _, args := range [][]string{{"escrow", "show"}, {"escrow", "ack"}} {
		code, out, errs := e.run("", args...)
		if code != 1 || out != "" || !strings.Contains(errs, "PGOPTIONS") || strings.Contains(errs, "statement_timeout") {
			t.Errorf("%v: exit %d, stdout %d bytes, stderr %q", args, code, len(out), errs)
		}
	}
	if e.acked() != "" {
		t.Fatal("an acknowledgement was written")
	}
}

// An acknowledgement file that cannot be read stops ack before anything is shown.
func TestEscrowAck_AnUnreadableAcknowledgementShowsNothing(t *testing.T) {
	e := newEscrowNode(t)
	e.stanza()
	if err := os.Mkdir(e.p.EscrowAcked(), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := e.run("", "escrow", "ack")
	if code != 1 || out != "" || strings.Count(errs, "\n") != 1 {
		t.Fatalf("exit %d, stdout %d bytes, stderr %q", code, len(out), errs)
	}
}
