package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// roSeams fakes the two read-only sessions' bootstrap calls and the reset;
// each records itself in the fake host's log. jobs runs as the clean-up.
func roSeams(t *testing.T, f *fakeHost, setErr error, resetErr error, jobs func(context.Context) error) *[]bootstrap.Secrets {
	t.Helper()
	var given []bootstrap.Secrets
	saved := []func(){
		swap(&bootstrapSetReadOnlyVerifier, func(ctx context.Context, c *pgx.Conn, s bootstrap.Secrets) error {
			f.record("set read-only verifier")
			given = append(given, s)
			return setErr
		}),
		swap(&bootstrapResetStatementStats, func(ctx context.Context, c *pgx.Conn) (bool, error) {
			f.record("reset statement stats")
			return resetErr == nil, resetErr
		}),
		swap(&bootstrapDeleteReadOnlyJobs, func(ctx context.Context, c *pgx.Conn) error {
			f.record("delete read-only jobs")
			if jobs != nil {
				return jobs(ctx)
			}
			return nil
		}),
	}
	t.Cleanup(func() {
		for _, r := range saved {
			r()
		}
	})
	return &given
}

// TestSetReadOnlyLogin_SuperuserParameters_ThenReset: one SCRAM session as
// the platform's superuser with the superuser list to the recorded
// postmaster, the verifier with the spec's secrets, then the reset; a reset
// failure is logged and not returned; a refused verifier is the error and
// nothing follows it; no phase-B cluster dials nothing.
func TestSetReadOnlyLogin_SuperuserParameters_ThenReset(t *testing.T) {
	a, f, s, pg := clSetup(t)
	s.FirstBoot = false
	s.Secrets.ReadOnlyPassword = "pw-read-only-0123456789"
	clToPhaseB(t, a, f, s)
	given := roSeams(t, f, nil, nil, nil)
	pg.targets = nil
	if err := a.SetReadOnlyLogin(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	st := clReadState(t, a, s)
	if len(pg.targets) != 1 {
		t.Fatalf("%d sessions", len(pg.targets))
	}
	tg := pg.targets[0]
	if tg.AllowTrust || !tg.Superuser || tg.User != "supabase_admin" || tg.Password != s.Secrets.SupabaseAdminPassword ||
		tg.PostmasterPid != st.PMPid || tg.LockTimeout != 0 || tg.StatementTimeout != 0 {
		t.Fatalf("target %+v", tg)
	}
	want := []string{fmt.Sprintf("dial supabase_admin pid=%d start=%d trust=false", st.PMPid, st.PMStart), "set read-only verifier", "reset statement stats"}
	if got := f.calls(); !slices.Equal(got, want) {
		t.Fatalf("calls %q", got)
	}
	if len(*given) != 1 || (*given)[0].ReadOnlyPassword != s.Secrets.ReadOnlyPassword {
		t.Fatalf("secrets given %d times", len(*given))
	}

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	roSeams(t, f, nil, errors.New("statement timeout\nforged line"), nil)
	if err := a.SetReadOnlyLogin(context.Background(), s); err != nil {
		t.Fatalf("a failed reset failed the call: %v", err)
	}
	if !strings.Contains(buf.String(), "level=WARN") || strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("log %q", buf.String())
	}

	roSeams(t, f, errors.New("permission denied"), nil, nil)
	f.resetLog()
	if err := a.SetReadOnlyLogin(context.Background(), s); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refused verifier: %v", err)
	}
	if slices.Contains(f.calls(), "reset statement stats") {
		t.Fatal("reset after a refused verifier")
	}

	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	pg.targets = nil
	if err := a.SetReadOnlyLogin(context.Background(), s); err == nil || len(pg.targets) != 0 {
		t.Fatalf("A-done: %v, %d dials", err, len(pg.targets))
	}
}

// TestDropReadOnlyJobs_StartupParameters: the clean-up's session is the
// platform's superuser session with the superuser list and lock_timeout 2s,
// statement_timeout 10s; nothing in it sets the replication role; the
// session sends the clean-up and nothing else.
func TestDropReadOnlyJobs_StartupParameters(t *testing.T) {
	a, f, s, pg := clSetup(t)
	s.FirstBoot = false
	clToPhaseB(t, a, f, s)
	roSeams(t, f, nil, nil, nil)
	pg.targets = nil
	if err := a.DropReadOnlyJobs(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	st := clReadState(t, a, s)
	if len(pg.targets) != 1 {
		t.Fatalf("%d sessions", len(pg.targets))
	}
	tg := pg.targets[0]
	if tg.AllowTrust || !tg.Superuser || tg.User != "supabase_admin" || tg.Password != s.Secrets.SupabaseAdminPassword ||
		tg.PostmasterPid != st.PMPid || tg.LockTimeout != 2*time.Second || tg.StatementTimeout != 10*time.Second {
		t.Fatalf("target %+v", tg)
	}
	if _, ok := pgsock.StartupParams(true)["session_replication_role"]; ok {
		t.Fatal("the superuser list sets the replication role")
	}
	want := []string{fmt.Sprintf("dial supabase_admin pid=%d start=%d trust=false", st.PMPid, st.PMStart), "delete read-only jobs"}
	if got := f.calls(); !slices.Equal(got, want) {
		t.Fatalf("calls %q", got)
	}
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	pg.targets = nil
	if err := a.DropReadOnlyJobs(context.Background(), s); err == nil || len(pg.targets) != 0 {
		t.Fatalf("A-done: %v, %d dials", err, len(pg.targets))
	}
}

// TestDropReadOnlyJobs_OwnDeadline: the clean-up runs under 15 s of its own
// whatever its caller's (a shorter one of the caller's stands). A deadline is
// worded by its cause: the run's own (no clean pass, with the reason), the
// caller's, or a pass's statement budget; any other error is returned as it is.
func TestDropReadOnlyJobs_OwnDeadline(t *testing.T) {
	a, f, s, _ := clSetup(t)
	s.FirstBoot = false
	clToPhaseB(t, a, f, s)
	var left time.Duration
	// The run as bootstrap ends it: at its context's end with the reason, or
	// at once with a pass's budget error.
	untilDone := func(ctx context.Context) error {
		d, ok := ctx.Deadline()
		if !ok {
			return errors.New("no deadline")
		}
		left = time.Until(d)
		<-ctx.Done()
		return fmt.Errorf("bootstrap: read-only jobs: last pass: the lock was not granted: %w", ctx.Err())
	}
	roSeams(t, f, nil, nil, untilDone)
	// Its own 15 s, whatever the caller's: the deadline it gives the run.
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	roSeams(t, f, nil, nil, func(ctx context.Context) error {
		d, _ := ctx.Deadline()
		left = time.Until(d)
		return nil
	})
	if err := a.DropReadOnlyJobs(ctx, s); err != nil || left > 15*time.Second || left < 14*time.Second {
		t.Fatalf("deadline in %v: %v", left, err)
	}
	// The run's own deadline (shortened here): no clean pass, with the reason.
	roSeams(t, f, nil, nil, untilDone)
	defer swap(&dropJobsDeadline, 200*time.Millisecond)()
	err := a.DropReadOnlyJobs(ctx, s)
	if err == nil || !strings.Contains(err.Error(), "no clean pass within") || !strings.Contains(err.Error(), "the lock was not granted") ||
		strings.Contains(err.Error(), "caller") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("own deadline: %v", err)
	}
	// The caller's shorter deadline: worded as the caller's.
	short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	err = a.DropReadOnlyJobs(short, s)
	if left > 100*time.Millisecond || err == nil || !strings.Contains(err.Error(), "the caller's deadline passed before a clean pass") ||
		strings.Contains(err.Error(), "no clean pass within") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller's deadline in %v: %v", left, err)
	}
	// A pass's statement budget with time left: worded as that.
	roSeams(t, f, nil, nil, func(context.Context) error {
		return fmt.Errorf("bootstrap: read-only jobs: %w", fmt.Errorf("%w: %w", pgsock.ErrBudget, context.DeadlineExceeded))
	})
	err = a.DropReadOnlyJobs(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "a pass ran out of its statement budget") || strings.Contains(err.Error(), "clean pass") {
		t.Fatalf("statement budget: %v", err)
	}
	// Any other error as it is.
	roSeams(t, f, nil, nil, func(context.Context) error { return &pgsock.ServerError{Code: "57014", Message: "canceling statement"} })
	err = a.DropReadOnlyJobs(context.Background(), s)
	var se *pgsock.ServerError
	if !errors.As(err, &se) || se.Code != "57014" || strings.Contains(err.Error(), "clean pass") || strings.Contains(err.Error(), "budget") {
		t.Fatalf("error %v", err)
	}
}
