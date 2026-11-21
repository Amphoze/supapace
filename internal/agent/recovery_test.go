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

	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// rcSetup is a layout-2 project whose cluster ran in phase B, with the
// recovery sessions faked.
func rcSetup(t *testing.T) (*Agent, *fakeHost, Spec, *clPG, *rcPG) {
	t.Helper()
	a, f, s, pg, _ := l2Setup(t)
	s.FirstBoot = false
	rc := rcFake(t, f)
	return a, f, s, pg, rc
}

var rcTargets = []struct {
	name string
	t    pgconf.RecoveryTarget
	last string // the command line's last element
}{
	{"time", pgconf.RecoveryTarget{Time: time.Date(2026, 3, 4, 5, 6, 7, 890000000, time.UTC), Timeline: "current"},
		"recovery_target_time=2026-03-04 05:06:07.89+00"},
	{"position", pgconf.RecoveryTarget{LSN: "0/3000060", Timeline: "2"}, "recovery_target_lsn=0/3000060"},
	{"end of the archive", pgconf.RecoveryTarget{Timeline: "latest"}, "archive_cleanup_command="},
}

func TestEnsureRecovery_Args(t *testing.T) {
	for _, tc := range rcTargets {
		t.Run(tc.name, func(t *testing.T) {
			a, f, s, _, _ := rcSetup(t)
			if err := a.EnsureRecovery(context.Background(), s, tc.t); err != nil {
				t.Fatal(err)
			}
			run := clOneRun(t, f, "pg-"+s.Ref)
			clCommon2(t, a, s, run, "R")
			clWantPairs(t, "recovery start", run, "--network", "none", "--stop-timeout", "45")
			fl := clFlags(run)
			for _, bad := range []string{"-e", "--env", "--env-file", "--ip", "--sysctl", "--restart"} {
				if slices.Contains(fl, bad) {
					t.Errorf("%s present: %q", bad, run)
				}
			}
			r, pd := a.p.RenderDir(s.Ref), a.p.ProjectDir(s.Ref)
			for _, v := range flagValues(run, "-v") {
				if strings.Contains(v, "pg_hba") || strings.Contains(v, "pg_ident") {
					t.Errorf("access file mounted: %s", v)
				}
			}
			clWantPairs(t, "recovery start", run, "-v", r+"/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro",
				"-v", pd+"/spool:/opt/supapace/spool", "-v", pd+"/rspool:/opt/supapace/rspool")
			for _, l := range flagValues(run, "--label") {
				if strings.HasPrefix(l, "supapace.config=") || strings.HasPrefix(l, "supapace.image=") {
					t.Errorf("carries %s", l)
				}
			}
			if strings.Contains(strings.Join(run, " "), "POSTGRES_PASSWORD") {
				t.Errorf("password variable in %q", run)
			}
			cl, err := pgconf.CommandLine(clFixture(t, "postgresql.conf"))
			if err != nil {
				t.Fatal(err)
			}
			pins, _ := pgconf.Pins(s.GUC)
			rec, _ := pgconf.RecoveryPins(tc.t)
			want := slices.Concat([]string{a.cfg.Images.Postgres, "postgres", "-D", "/etc/postgresql"}, cl, pins,
				pgconf.RecoveryExtensionPins(), recoveryStartPins, rec)
			got := positional(run)
			if !slices.Equal(got, want) {
				t.Fatalf("command\n got %q\nwant %q", got, want)
			}
			if got[len(got)-1] != tc.last {
				t.Fatalf("last element %q, want %q", got[len(got)-1], tc.last)
			}
			// The override file is the pinned one.
			conf := clRead(t, a.p.RenderDir(s.Ref)+"/conf.d/"+pgconf.OverrideFile)
			if w, _ := pgconf.OverridesPinned(s.GUC, s.MemMB); !bytes.Equal(conf, w) {
				t.Fatalf("override file is not OverridesPinned: %q", conf)
			}
			if c := clCtr(t, f, "pg-"+s.Ref); !c.Running {
				t.Fatal("not started")
			}
		})
	}
}

// A target the pins refuse touches nothing: no container removed, created or
// started, no file rendered, no state written.
func TestEnsureRecovery_RefusedTargetTouchesNothing(t *testing.T) {
	a, f, s, _, _ := rcSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseB, PMPid: 77, PMStart: 770})
	f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, Pid: 77, Labels: map[string]string{labelPhase: "B"}})
	f.resetLog()
	err := a.EnsureRecovery(context.Background(), s, pgconf.RecoveryTarget{Timeline: "current"})
	if !errors.Is(err, pgconf.ErrGUCValue) {
		t.Fatalf("err %v", err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutations %q", m)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "write ") {
			t.Fatalf("wrote %s", c)
		}
	}
	if st := clReadState(t, a, s); st.Phase != PhaseB || st.PMPid != 77 {
		t.Fatalf("state %+v", st)
	}
}

func TestEnsureRecovery_GateBeforeStart(t *testing.T) {
	a, f, s, pg, _ := rcSetup(t)
	if err := a.EnsureRecovery(context.Background(), s, rcTargets[0].t); err != nil {
		t.Fatal(err)
	}
	clGateThenStart(t, f.calls(), s.Ref)
	if len(pg.targets) != 0 {
		t.Fatal("dialled the recovery start: it waits for nothing")
	}
	// A refused gate: the created container is removed, nothing started,
	// the state untouched.
	for _, fault := range []func(a *Agent, f *fakeHost){
		func(a *Agent, f *fakeHost) { f.nftErr = nft.ErrDrift },
		func(a *Agent, f *fakeHost) { a.SetContainmentFailed(true) },
	} {
		a, f, s, _, _ := rcSetup(t)
		clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseB, PMPid: 77, PMStart: 770})
		fault(a, f)
		f.resetLog()
		wantContainment(t, a.EnsureRecovery(context.Background(), s, rcTargets[0].t), "recovery start")
		for _, c := range f.calls() {
			if strings.HasPrefix(c, "docker start ") {
				t.Fatalf("started after a refused gate: %s", c)
			}
		}
		if _, ok := f.ctrs["pg-"+s.Ref]; ok {
			t.Fatal("refused container left behind")
		}
		if st := clReadState(t, a, s); st.Phase != PhaseB || st.PMPid != 77 {
			t.Fatalf("state changed: %+v", st)
		}
	}
}

func TestEnsureRecovery_NeverWipesNeverBootstraps(t *testing.T) {
	for _, st := range []*State{nil, {Phase: PhaseB, PMPid: 77, PMStart: 770}, {Phase: PhaseR, PMPid: 78, PMStart: 780}, {Phase: PhaseADone}} {
		name := "no state"
		if st != nil {
			name = st.Phase
		}
		t.Run(name, func(t *testing.T) {
			a, f, s, _, rc := rcSetup(t)
			if st != nil {
				st.Epoch, st.Generation = s.Epoch, s.Generation
				clState(t, a, s, *st)
			}
			if err := a.EnsureRecovery(context.Background(), s, rcTargets[2].t); err != nil {
				t.Fatal(err)
			}
			for _, c := range f.calls() {
				if strings.Contains(c, "task-"+s.Ref+"-wipe") || c == "bootstrap run" || c == "assert" || c == "assert hba" ||
					strings.HasPrefix(c, "dial ") {
					t.Fatalf("%s in a recovery start", c)
				}
			}
			if rc.rekeyCalls != 0 || rc.inCalls != 0 {
				t.Fatal("a session statement in the start")
			}
		})
	}
}

func TestEnsureRecovery_WritesStateRWhenAbsent(t *testing.T) {
	a, f, s, pg, _ := rcSetup(t)
	if _, ok, _ := a.readState(s.Ref); ok {
		t.Fatal("state present before")
	}
	pg.starts = map[int]uint64{}
	if err := a.EnsureRecovery(context.Background(), s, rcTargets[1].t); err != nil {
		t.Fatal(err)
	}
	c := clCtr(t, f, "pg-"+s.Ref)
	st := clReadState(t, a, s)
	if st != (State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseR, PMPid: c.Pid, PMStart: uint64(c.Pid) * 10}) {
		t.Fatalf("state %+v, container pid %d", st, c.Pid)
	}
	// A second start (a crash after it, a resumed step) replaces the first
	// container — never two on one directory — and records the new process.
	if err := a.EnsureRecovery(context.Background(), s, rcTargets[1].t); err != nil {
		t.Fatal(err)
	}
	c2 := clCtr(t, f, "pg-"+s.Ref)
	calls := f.calls()
	rm := clLastIndex(calls, "docker rm -f -v -- pg-"+s.Ref)
	create := slices.IndexFunc(calls[max(rm, 0):], clIsClusterRun(s.Ref))
	if c2.ID == c.ID || rm < 0 || create < 0 {
		t.Fatalf("the first container was not removed before the second create:\n%s", strings.Join(calls, "\n"))
	}
	if st := clReadState(t, a, s); st.Phase != PhaseR || st.PMPid != c2.Pid {
		t.Fatalf("state %+v, container pid %d", st, c2.Pid)
	}
}

// A start that fails after the create leaves the state as it was: the next
// call removes the container and starts again.
func TestEnsureRecovery_FailedStartLeavesStateAsItWas(t *testing.T) {
	a, f, s, _, _ := rcSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseB, PMPid: 77, PMStart: 770})
	f.failVerb["start"] = errors.New("docker: start failed")
	if err := a.EnsureRecovery(context.Background(), s, rcTargets[0].t); err == nil {
		t.Fatal("no error")
	}
	if st := clReadState(t, a, s); st.Phase != PhaseB || st.PMPid != 77 {
		t.Fatalf("state %+v", st)
	}
	delete(f.failVerb, "start")
	if err := a.EnsureRecovery(context.Background(), s, rcTargets[0].t); err != nil {
		t.Fatal(err)
	}
	if st := clReadState(t, a, s); st.Phase != PhaseR {
		t.Fatalf("state %+v", st)
	}
}

func TestEnsureRecovery_RefusedForLayout1(t *testing.T) {
	for _, layout := range []int{0, 1, 3} {
		a, f, s, _, _ := rcSetup(t)
		s.Layout = layout
		f.resetLog()
		if err := a.EnsureRecovery(context.Background(), s, rcTargets[2].t); err == nil || !strings.Contains(err.Error(), "layout 2") {
			t.Fatalf("layout %d: %v", layout, err)
		}
		if len(f.calls()) != 0 {
			t.Fatalf("layout %d: calls %q", layout, f.calls())
		}
	}
}

func TestEnsureRecovery_StateChecks(t *testing.T) {
	a, f, s, _, _ := rcSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch + 1, Generation: s.Generation, Phase: PhaseB})
	f.resetLog()
	if err := a.EnsureRecovery(context.Background(), s, rcTargets[2].t); !errors.Is(err, ErrEpochDivergence) {
		t.Fatalf("err %v", err)
	}
	if len(f.mutations()) != 0 {
		t.Fatal("mutated")
	}
}

// rcStarted is a project whose recovery start is running.
func rcStarted(t *testing.T) (*Agent, *fakeHost, Spec, *clPG, *rcPG) {
	t.Helper()
	a, f, s, pg, rc := rcSetup(t)
	if err := a.EnsureRecovery(context.Background(), s, rcTargets[2].t); err != nil {
		t.Fatal(err)
	}
	f.resetLog()
	return a, f, s, pg, rc
}

func TestRecoveryState_ConnectErrorAndBudgetAreNotPromoted_OtherErrorsAreErrors(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		ok   bool
	}{
		{"connect", fmt.Errorf("pgsock: project x: socket: %w", pgsock.ErrConnect), true},
		{"budget", pgsock.Clean(fmt.Errorf("%w: connect", pgsock.ErrBudget)), true},
		{"no socket yet", pgsock.ErrNotSocket, true},
		{"starting up", pgsock.Clean(&pgsock.ServerError{Code: "57P03", Message: "the database system is not yet accepting connections"}), true},
		{"peer", pgsock.ErrPeer, false},
		{"scram params", pgsock.ErrScramParams, false},
		{"cleartext", pgsock.ErrCleartextRequested, false},
		{"other server error", pgsock.Clean(&pgsock.ServerError{Code: "28000", Message: "role is not permitted to log in"}), false},
		{"environment", pgsock.ErrEnvironment, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, _, s, pg, rc := rcStarted(t)
			pg.dialAlways = c.err
			promoted, exited, err := a.RecoveryState(context.Background(), s)
			if promoted || exited || (err == nil) != c.ok {
				t.Fatalf("promoted %v exited %v err %v", promoted, exited, err)
			}
			if rc.inCalls != 0 {
				t.Fatal("asked after a failed dial")
			}
		})
	}
	// A budget error of the statement is not promoted either; another error of
	// it is an error.
	a, _, s, _, rc := rcStarted(t)
	rc.inRecoveryErr = pgsock.Clean(fmt.Errorf("%w: statement", pgsock.ErrBudget))
	if p, e, err := a.RecoveryState(context.Background(), s); p || e || err != nil {
		t.Fatalf("statement budget: %v %v %v", p, e, err)
	}
	rc.inRecoveryErr = errors.New("bootstrap: pg_is_in_recovery: 2 rows")
	if _, _, err := a.RecoveryState(context.Background(), s); err == nil {
		t.Fatal("a malformed answer is not an error")
	}
	// The answer.
	rc.inRecoveryErr = nil
	rc.inRecovery = true
	if p, e, err := a.RecoveryState(context.Background(), s); p || e || err != nil {
		t.Fatalf("in recovery: %v %v %v", p, e, err)
	}
	rc.inRecovery = false
	if p, e, err := a.RecoveryState(context.Background(), s); !p || e || err != nil {
		t.Fatalf("promoted: %v %v %v", p, e, err)
	}
}

func TestRecoveryState_TrustSessionToTheRecordedStart(t *testing.T) {
	a, f, s, pg, _ := rcStarted(t)
	if _, _, err := a.RecoveryState(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	c := clCtr(t, f, "pg-"+s.Ref)
	tg := pg.targets[len(pg.targets)-1]
	if !tg.AllowTrust || tg.Password != "" || !tg.Superuser || tg.User != "supabase_admin" || tg.PostmasterPid != c.Pid ||
		tg.PostmasterStart != uint64(c.Pid)*10 || tg.Ref != s.Ref || tg.UID != s.UID || tg.Budget != (pgsock.Budget{}) {
		t.Fatalf("target %v", tg)
	}
}

func TestRecoveryState_ExitedFromDockerOnly(t *testing.T) {
	a, f, s, pg, rc := rcStarted(t)
	// The server would say it promoted; Docker says the container exited.
	rc.inRecovery = false
	f.mu.Lock()
	f.ctrs["pg-"+s.Ref].Running = false
	f.mu.Unlock()
	if p, e, err := a.RecoveryState(context.Background(), s); p || !e || err != nil {
		t.Fatalf("stopped: %v %v %v", p, e, err)
	}
	f.mu.Lock()
	delete(f.ctrs, "pg-"+s.Ref)
	f.mu.Unlock()
	if p, e, err := a.RecoveryState(context.Background(), s); p || !e || err != nil {
		t.Fatalf("removed: %v %v %v", p, e, err)
	}
	if len(pg.targets) != 0 || rc.inCalls != 0 {
		t.Fatal("asked the server about an exited container")
	}
	// Running, whatever the server says about itself, is not exited.
	a, _, s, pg, _ = rcStarted(t)
	pg.dialAlways = pgsock.ErrPeer
	if _, e, _ := a.RecoveryState(context.Background(), s); e {
		t.Fatal("a failed session read as exited")
	}
	// A Docker error is an error, not exited.
	a, f, s, _, _ = rcStarted(t)
	f.failInspect["pg-"+s.Ref] = errors.New("docker: inspect failed")
	if _, e, err := a.RecoveryState(context.Background(), s); e || err == nil {
		t.Fatalf("inspect error: exited %v err %v", e, err)
	}
}

func TestRecoveryState_NeedsARecordedRecoveryStart(t *testing.T) {
	for _, st := range []*State{nil, {Phase: PhaseB, PMPid: 77, PMStart: 770}, {Phase: PhaseADone}} {
		a, f, s, pg, _ := rcSetup(t)
		if st != nil {
			st.Epoch, st.Generation = s.Epoch, s.Generation
			clState(t, a, s, *st)
		}
		f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, Pid: 77})
		if _, _, err := a.RecoveryState(context.Background(), s); err == nil {
			t.Fatalf("state %v: no error", st)
		}
		if _, err := a.Rekey(context.Background(), s); err == nil {
			t.Fatalf("state %v: re-key without a recovery start", st)
		}
		if len(pg.targets) != 0 {
			t.Fatal("dialled")
		}
	}
}

func TestRekey_TrustSession_SuperuserParams(t *testing.T) {
	a, f, s, pg, rc := rcStarted(t)
	if _, err := a.Rekey(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if len(pg.targets) != 1 {
		t.Fatalf("%d sessions, want one", len(pg.targets))
	}
	c := clCtr(t, f, "pg-"+s.Ref)
	tg := pg.targets[0]
	if !tg.AllowTrust || tg.Password != "" || !tg.Superuser || tg.User != "supabase_admin" || tg.PostmasterPid != c.Pid ||
		tg.PostmasterStart != uint64(c.Pid)*10 || tg.ProjectsDir != a.p.ProjectsDir() || tg.UID != s.UID {
		t.Fatalf("target %v", tg)
	}
	if rc.rekeySecrets.SupabaseAdminPassword != s.Secrets.SupabaseAdminPassword ||
		rc.rekeySecrets.PostgresPassword != s.Secrets.PostgresPassword ||
		rc.rekeySecrets.AuthenticatorPassword != s.Secrets.AuthenticatorPassword {
		t.Fatal("re-keyed with other secrets than the spec's")
	}
	// Superuser carries the nineteen (pgsock's list, tested there).
	if _, ok := pgsock.StartupParams(tg.Superuser)["log_min_error_statement"]; !ok {
		t.Fatal("superuser list without its parameters")
	}
}

func TestRekey_ReturnsTimeline(t *testing.T) {
	a, _, s, _, rc := rcStarted(t)
	rc.timeline = 7
	if tl, err := a.Rekey(context.Background(), s); tl != 7 || err != nil {
		t.Fatalf("timeline %d err %v", tl, err)
	}
	rc.timelineErr = errors.New("bootstrap: timeline: not 8 hex digits")
	if tl, err := a.Rekey(context.Background(), s); tl != 0 || err == nil {
		t.Fatalf("timeline %d err %v", tl, err)
	}
}

func TestRekey_Order_VerifiersThenRoleThenTimelineThenReset(t *testing.T) {
	a, f, s, _, _ := rcStarted(t)
	if _, err := a.Rekey(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "dial ") || slices.Contains([]string{"rekey", "in recovery", "read timeline", "reset statement stats"}, c) {
			got = append(got, strings.Fields(c)[0])
		}
	}
	// bootstrap.Rekey sends the verifier statements first, then the backup
	// role's (tested in bootstrap); nothing of the session precedes it.
	if want := []string{"dial", "rekey", "read", "reset"}; !slices.Equal(got, want) {
		t.Fatalf("session %q, want %q", got, want)
	}
	// A failed re-key ends the session there.
	a, f, s, _, rc := rcStarted(t)
	rc.rekeyErr = pgsock.Clean(&pgsock.ServerError{Code: "25006", Message: "cannot execute ALTER ROLE in a read-only transaction"})
	if _, err := a.Rekey(context.Background(), s); err == nil {
		t.Fatal("no error")
	}
	for _, c := range f.calls() {
		if c == "read timeline" || c == "reset statement stats" || c == "in recovery" {
			t.Fatalf("%s after a failed re-key", c)
		}
	}
	var se *pgsock.ServerError
	if _, err := a.Rekey(context.Background(), s); !errors.As(err, &se) || se.Code != "25006" {
		t.Fatalf("server refusal not matchable: %v", err)
	}
}

func TestRekey_ResetFailureIsLoggedNotReturned(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	a, _, s, _, rc := rcStarted(t)
	rc.timeline = 3
	rc.resetErr = pgsock.Clean(&pgsock.ServerError{Code: "XX000", Message: "tenant\nfunction\x1b[2J says no"})
	if tl, err := a.Rekey(context.Background(), s); tl != 3 || err != nil {
		t.Fatalf("timeline %d err %v", tl, err)
	}
	out := logs.String()
	if !strings.Contains(out, "statement statistics not reset") || !strings.Contains(out, "ref="+s.Ref) ||
		strings.Contains(out, "\x1b") || strings.Count(out, "\n") != 1 {
		t.Fatalf("log %q", out)
	}
	logs.Reset()
	rc.resetErr, rc.reset = nil, false
	if _, err := a.Rekey(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "the function is not there") {
		t.Fatalf("log %q", logs.String())
	}
}

// A re-key cut short (a crash between two of its statements) is repeated in
// a session that needs no password: the platform is never locked out.
func TestRekey_RepeatedAfterAFailure(t *testing.T) {
	a, _, s, pg, rc := rcStarted(t)
	rc.rekeyErr = pgsock.Clean(fmt.Errorf("%w: statement", pgsock.ErrBudget))
	if _, err := a.Rekey(context.Background(), s); !pgsock.IsBudget(err) {
		t.Fatalf("err %v", err)
	}
	rc.rekeyErr = nil
	if _, err := a.Rekey(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	for _, tg := range pg.targets {
		if !tg.AllowTrust || tg.Password != "" {
			t.Fatalf("target %v", tg)
		}
	}
}

// A recovery start recorded for another epoch (or a newer generation) is not
// this spec's: neither the poll nor the re-key opens a session to it.
func TestRecoveryStateAndRekey_StateOfAnotherEpochRefused(t *testing.T) {
	for _, st := range []State{{Epoch: 2, Generation: 1, Phase: PhaseR, PMPid: 77, PMStart: 770},
		{Epoch: 1, Generation: 9, Phase: PhaseR, PMPid: 77, PMStart: 770}} {
		a, f, s, pg, _ := rcSetup(t)
		s.Epoch, s.Generation = 1, 1
		clState(t, a, s, st)
		f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, Pid: 77})
		if _, _, err := a.RecoveryState(context.Background(), s); !errors.Is(err, ErrEpochDivergence) && !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("%+v: poll: %v", st, err)
		}
		if _, err := a.Rekey(context.Background(), s); !errors.Is(err, ErrEpochDivergence) && !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("%+v: re-key: %v", st, err)
		}
		if len(pg.targets) != 0 {
			t.Fatal("dialled")
		}
	}
}

// TestEnsureRecovery_WorkerAndDelayPins: the recovery start's own pins, by
// value, between the extension pins and the recovery pins.
func TestEnsureRecovery_WorkerAndDelayPins(t *testing.T) {
	a, f, s, _, _ := rcSetup(t)
	if err := a.EnsureRecovery(context.Background(), s, rcTargets[0].t); err != nil {
		t.Fatal(err)
	}
	cmd := positional(clOneRun(t, f, "pg-"+s.Ref))
	ext := pgconf.RecoveryExtensionPins()
	want := []string{"-c", "pre_auth_delay=0", "-c", "pg_net.database_name=", "-c", "cron.database_name=", "-c", "autovacuum=off", "-c", "max_logical_replication_workers=0"}
	i := slices.Index(cmd, ext[len(ext)-1])
	if i < 0 || !slices.Equal(cmd[i+1:i+1+len(want)], want) {
		t.Fatalf("command %q", cmd)
	}
	rec, _ := pgconf.RecoveryPins(rcTargets[0].t)
	if !slices.Equal(cmd[i+1+len(want):], rec) {
		t.Fatalf("recovery pins do not follow: %q", cmd)
	}
}

// A poll whose session is cut because the server exits reads exited.
func TestRecoveryState_SessionCutByTheServersExitIsExited(t *testing.T) {
	a, f, s, pg, _ := rcStarted(t)
	pg.onDial = func(pgsock.Target) {
		f.mu.Lock()
		f.ctrs["pg-"+s.Ref].Running = false
		f.mu.Unlock()
	}
	pg.dialAlways = errors.New("pgsock: project x: login: read: connection reset by peer")
	if p, e, err := a.RecoveryState(context.Background(), s); p || !e || err != nil {
		t.Fatalf("promoted %v exited %v err %v", p, e, err)
	}
	// Still running: the same failure is an error.
	a, _, s, pg, _ = rcStarted(t)
	pg.dialAlways = errors.New("pgsock: project x: login: read: connection reset by peer")
	if _, e, err := a.RecoveryState(context.Background(), s); e || err == nil {
		t.Fatalf("exited %v err %v", e, err)
	}
}
