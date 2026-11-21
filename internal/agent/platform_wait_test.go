package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func cpSessions(f *fakeHost) int {
	n := 0
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "session ") {
			n++
		}
	}
	return n
}

// On a stamped node with its container in place the ensure opens no
// session: a repair round never waits for the database.
func TestEnsureCP_StampedNodeOpensNoSession(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	f.resetLog()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if n := cpSessions(f); n != 0 || len(f.mutations()) != 0 {
		t.Fatalf("a later ensure opened %d sessions, mutations %q", n, f.mutations())
	}
}

// A first start that stops before it answers ends the wait at once, with an
// error that says so; the node is not stamped.
func TestEnsureCP_FirstStartThatStopsIsAnError(t *testing.T) {
	a, f, cf := cpSetup(t)
	defer swap(&cpAnswerWait, 3*time.Second)()
	cf.session = func(context.Context, string) (bool, int64, error) {
		f.ctrs[cpName].Running = false
		return false, 0, errCPNotUp
	}
	err := a.EnsureControlPlaneDB(context.Background())
	if err == nil || !strings.Contains(err.Error(), "stopped before it answered") {
		t.Fatalf("got %v, want the stop reported", err)
	}
	if _, err := os.Lstat(a.cpStampPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stamped although the first start never answered: %v", err)
	}
}

// A session that fails for another reason than a server not yet up ends the
// wait with that error, at the first attempt.
func TestEnsureCP_SessionErrorEndsTheWaitAtOnce(t *testing.T) {
	a, f, cf := cpSetup(t)
	defer swap(&cpAnswerWait, 3*time.Second)()
	boom := errors.New("permission denied for function")
	cf.session = func(context.Context, string) (bool, int64, error) { return false, 0, boom }
	err := a.EnsureControlPlaneDB(context.Background())
	if !errors.Is(err, boom) || strings.Contains(err.Error(), "did not answer within") {
		t.Fatalf("got %v, want the session's error itself", err)
	}
	if n := cpSessions(f); n != 1 {
		t.Fatalf("%d sessions, want one", n)
	}
	if runs := cpRuns(f); len(runs) != 1 {
		t.Fatalf("starts %d, want the first only", len(runs))
	}
}
