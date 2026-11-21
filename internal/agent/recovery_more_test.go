package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/pgsock"
)

// A container of the project that cannot be removed: no second one is created
// or started beside it, and the state stays as it was.
func TestEnsureRecovery_ContainerThatCannotBeRemovedGetsNoSecondServer(t *testing.T) {
	for _, running := range []bool{true, false} {
		a, f, s, _, _ := rcSetup(t)
		clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseB, PMPid: 77, PMStart: 770})
		f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: running, Pid: 77, Labels: map[string]string{labelPhase: "B"}})
		f.failVerb["rm"] = errors.New("docker rm: daemon busy")
		f.resetLog()
		if err := a.EnsureRecovery(context.Background(), s, rcTargets[2].t); err == nil {
			t.Fatalf("running %v: no error", running)
		}
		calls := f.calls()
		if slices.ContainsFunc(calls, clIsClusterRun(s.Ref)) || slices.ContainsFunc(calls, clPrefix("docker start ")) {
			t.Fatalf("running %v: created or started beside a container that was not removed:\n%s", running, strings.Join(calls, "\n"))
		}
		if st := clReadState(t, a, s); st.Phase != PhaseB || st.PMPid != 77 {
			t.Fatalf("running %v: state %+v", running, st)
		}
	}
}

// A recovery start left behind by a stop between the container's start and
// the state write (the state still names an earlier recovery start's
// process): the poll is an error, never "still replaying", and the re-key
// opens no session to the unrecorded process.
func TestRecoveryState_UnrecordedProcessIsAnErrorNotStillReplaying(t *testing.T) {
	a, _, s, pg, rc := rcStarted(t)
	pg.dialAlways = pgsock.ErrPeer // what the dial answers for a process other than the recorded one
	if p, e, err := a.RecoveryState(context.Background(), s); p || e || !errors.Is(err, pgsock.ErrPeer) {
		t.Fatalf("poll: promoted %v exited %v err %v", p, e, err)
	}
	if _, err := a.Rekey(context.Background(), s); !errors.Is(err, pgsock.ErrPeer) {
		t.Fatalf("re-key: %v", err)
	}
	if rc.rekeyCalls != 0 || rc.inCalls != 0 {
		t.Fatal("a statement was sent")
	}
}

// The reset's error is cut and cleared of control characters by the caller
// too, whatever the callee returns: one log line, at most 256 bytes of it.
func TestRekey_ResetErrorIsSanitisedWhateverItsSource(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	a, _, s, _, rc := rcStarted(t)
	rc.resetErr = errors.New("raw\x1b[2J\x00" + strings.Repeat("x", 4096) + "TAIL")
	if _, err := a.Rekey(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if strings.ContainsAny(out, "\x1b\x00") || strings.Contains(out, "TAIL") || len(out) > 600 || strings.Count(out, "\n") != 1 {
		t.Fatalf("log (%d bytes) %q", len(out), out)
	}
}

// A spec without the project's ids or limits, or with a ref that is no ref,
// is refused before anything is read or touched.
func TestEnsureRecovery_InvalidSpecTouchesNothing(t *testing.T) {
	for name, change := range map[string]func(*Spec){
		"no uid":    func(s *Spec) { s.UID = 0 },
		"no memory": func(s *Spec) { s.MemMB = 0 },
		"bad ref":   func(s *Spec) { s.Ref = "../" + s.Ref[3:] },
	} {
		a, f, s, _, _ := rcSetup(t)
		change(&s)
		f.resetLog()
		if err := a.EnsureRecovery(context.Background(), s, rcTargets[2].t); err == nil {
			t.Fatalf("%s: no error", name)
		}
		if c := f.calls(); len(c) != 0 {
			t.Fatalf("%s: calls %q", name, c)
		}
	}
}

// The poll and the re-key refuse such a spec as well, before any session.
func TestRecoveryStateAndRekey_InvalidSpecOpensNoSession(t *testing.T) {
	a, _, s, pg, _ := rcStarted(t)
	s.UID = 0
	if _, _, err := a.RecoveryState(context.Background(), s); err == nil {
		t.Fatal("poll: no error")
	}
	if _, err := a.Rekey(context.Background(), s); err == nil {
		t.Fatal("re-key: no error")
	}
	if len(pg.targets) != 0 {
		t.Fatal("dialled")
	}
}
