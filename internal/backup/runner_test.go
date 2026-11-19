package backup

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/store"
)

// ───────── Start ─────────

func TestStart_KillsContainersRemovesJobFilesAndInterrupts(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	id := e.submit(ref, "check")
	j, ok, err := e.st.NextJob(context.Background(), "backup")
	if err != nil || !ok || j.ID != id {
		t.Fatalf("pick: %v %v %v", j.ID, ok, err)
	}
	must(t, e.r.Start(context.Background()))
	if got := e.ag.called(); !slices.Equal(got, []string{"KillJobs "}) {
		t.Fatalf("calls = %q, want one KillJobs of every subject", got)
	}
	if got := e.job(id); got.State != "failed" || got.Code != "interrupted" {
		t.Fatalf("job = %+v, want failed/interrupted", got)
	}
}

func TestStart_SlotsAreFreedOnlyAfterEveryJobContainerIsGone(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	id := e.submit(ref, "check")
	_, ok, err := e.st.NextJob(context.Background(), "backup")
	if !ok || err != nil {
		t.Fatal("no pick")
	}
	e.ag.killErr = errTest
	if err := e.r.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded although the job containers could not be removed")
	}
	if got := e.job(id); got.State != "running" {
		t.Fatalf("job = %+v, want still running: its slot must stay held", got)
	}
	// Control: once the removal succeeds the slot is freed.
	e.ag.killErr = nil
	must(t, e.r.Start(context.Background()))
	if got := e.job(id); got.State != "failed" {
		t.Fatalf("job = %+v after a successful Start", got)
	}
}

// ───────── Cancel ─────────

func TestCancel_KillsRunningJobOfOperation(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.ag.setScript("check", blockUntilStopped)
	op, id := e.parked(ref, "check", "")
	_, other := e.parked(e.project("active"), "check", "")
	go e.turn("backup")
	e.ag.waitStart(t)
	go e.turn("backup")
	e.ag.waitStart(t)
	// The operation leaves waiting_job first (an abort), then its jobs are cancelled.
	_, err := e.db.Exec(context.Background(), "update operation set state = 'aborting' where id = $1", op)
	must(t, err)
	must(t, e.r.Cancel(bounded(t), op))
	if got := e.job(id); got.State != "failed" || got.Code != "cancelled" {
		t.Fatalf("job = %+v, want failed/cancelled once Cancel returns", got)
	}
	if got := e.job(other); got.State != "running" {
		t.Fatalf("another operation's job = %+v, want still running", got)
	}
}

func TestCancelSubject_CancelsQueuedAndKillsRunning(t *testing.T) {
	e := newEnv(t)
	ref, other := e.project("active"), e.project("active")
	e.ag.setScript("push", blockUntilStopped)
	running := e.submit(ref, "push")
	go e.turn("push")
	e.ag.waitStart(t)
	queued := e.submit(ref, "check")
	keep := e.submit(other, "check")
	must(t, e.r.CancelSubject(bounded(t), ref))
	for _, id := range []int64{running, queued} {
		if got := e.job(id); got.State != "failed" || got.Code != "cancelled" {
			t.Fatalf("job %d = %+v, want failed/cancelled", id, got)
		}
	}
	if got := e.job(keep); got.State != "queued" {
		t.Fatalf("another subject's job = %+v", got)
	}
}

// A job cancelled between its pick and its launch is never launched.
func TestCancel_BeforeLaunchIsNeverLaunched(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	id := e.submit(ref, "check")
	j, _, err := e.st.NextJob(context.Background(), "backup")
	must(t, err)
	done := make(chan error)
	reread := func(ctx context.Context) ([]store.Job, error) { return e.st.CancelSubjectJobs(ctx, ref) }
	go func() { done <- e.r.stop(bounded(t), []store.Job{j}, reread, "cancelled") }()
	e.eventually("the stop to be registered", func() bool {
		e.r.mu.Lock()
		defer e.r.mu.Unlock()
		return e.r.active[id] != nil
	})
	e.r.run(context.Background(), j)
	must(t, <-done)
	if got := e.job(id); got.Code != "cancelled" || slices.ContainsFunc(e.ag.called(), func(c string) bool { return strings.HasPrefix(c, "RunJob") }) {
		t.Fatalf("job = %+v, calls %q", got, e.ag.called())
	}
}

// ───────── PushNow ─────────

func pushResult(complete bool) []byte {
	p := okPush()
	p.Complete = complete
	return line(p)
}

// pushNow runs PushNow while taking push-lane turns until it answers.
func (e *env) pushNow(subject string, wait time.Duration) string {
	e.t.Helper()
	res := make(chan string, 1)
	go func() {
		out, err := e.r.PushNow(context.Background(), subject, wait)
		if err != nil {
			out = "error: " + err.Error()
		}
		res <- out
	}()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case out := <-res:
			return out
		default:
			e.turn("push")
			time.Sleep(time.Millisecond)
		}
	}
	e.t.Fatal("PushNow did not answer")
	return ""
}

func TestPushNow_RepeatsUntilCompleteWithinTheWait(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		e := newEnv(t)
		ref := e.project("active")
		n := 0
		e.ag.setScript("push", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			n++
			return agent.JobResult{Result: pushResult(n >= 2)}, nil
		})
		if got := e.pushNow(ref, time.Minute); got != "ok" {
			t.Fatalf("outcome %q, want ok", got)
		}
		if n != 2 {
			t.Fatalf("%d push jobs, want 2: one incomplete, then a complete one", n)
		}
	})
	t.Run("incomplete", func(t *testing.T) {
		e := newEnv(t)
		ref := e.project("active")
		e.ag.setScript("push", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{Result: pushResult(false)}, nil
		})
		// PushNow reads its job once per step; each push takes 40 s of a
		// 100 s wait.
		step := make(chan struct{})
		e.r.pushWait = func(ctx context.Context) {
			select {
			case <-step:
			case <-ctx.Done():
			}
		}
		res := make(chan string, 1)
		go func() { out, _ := e.r.PushNow(context.Background(), ref, 100*time.Second); res <- out }()
		var out string
		for n := 1; out == ""; n++ {
			e.eventually("a queued push", func() bool {
				return e.count("select count(*) from backup_job where kind = 'push' and state = 'queued'") == 1
			})
			if !e.turn("push") {
				t.Fatal("not picked")
			}
			e.clock.Add(40 * time.Second)
			step <- struct{}{}
			e.eventually("an answer or the next push", func() bool {
				select {
				case out = <-res:
					return true
				default:
					return e.count("select count(*) from backup_job where kind = 'push' and state = 'queued'") == 1
				}
			})
			if out != "" && n != 3 {
				t.Fatalf("answered %q after %d pushes, want 3 (40 s each within a wait of 100 s)", out, n)
			}
		}
		if out != "incomplete" {
			t.Fatalf("outcome %q, want incomplete", out)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		e := newEnv(t)
		ref := e.project("active")
		res := make(chan string, 1)
		go func() { out, _ := e.r.PushNow(context.Background(), ref, 10*time.Second); res <- out }()
		e.eventually("a queued push", func() bool { return e.count("select count(*) from backup_job where kind = 'push'") == 1 })
		e.clock.Add(11 * time.Second)
		if got := <-res; got != "timeout" {
			t.Fatalf("outcome %q, want timeout", got)
		}
	})
	t.Run("failed", func(t *testing.T) {
		e := newEnv(t)
		ref := e.project("active")
		e.ag.setScript("push", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{ExitCode: 1, Result: failLine("repository", "no")}, nil
		})
		if got := e.pushNow(ref, time.Minute); got != "failed" {
			t.Fatalf("outcome %q, want failed", got)
		}
	})
	t.Run("zero wait asks once and returns", func(t *testing.T) {
		e := newEnv(t)
		ref := e.project("active")
		out, err := e.r.PushNow(context.Background(), ref, 0)
		must(t, err)
		out2, err := e.r.PushNow(context.Background(), ref, 0)
		must(t, err)
		if out != "timeout" || out2 != "timeout" || e.count("select count(*) from backup_job where kind = 'push' and state = 'queued'") != 1 {
			t.Fatalf("outcomes %q %q; a second ask must not queue a second push", out, out2)
		}
	})
}

// ───────── off-site state ─────────

func TestOffsite_ThreeStates(t *testing.T) {
	r := New(nil, nil, nil, [32]byte{}, testConfig(), nodecfgPaths(t))
	if got := r.Offsite(); got != "undeclared" {
		t.Fatalf("before SetOffsite: %q", got)
	}
	for _, st := range []offsite.State{offsite.StatePartial, offsite.StateDeclared, offsite.StateUndeclared} {
		r.SetOffsite(offsite.Declaration{}, st, nil)
		if got := r.Offsite(); got != string(st) {
			t.Fatalf("Offsite() = %q, want %q", got, st)
		}
	}
}

func TestJobSpec_AddrsAreTheLoadedSet(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	withSeams(t, nil, nil)
	d := e.declare()
	addrs := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:443"), netip.MustParseAddrPort("198.51.100.7:9000")}
	e.r.SetOffsite(d, offsite.StateDeclared, addrs)
	addrs[0] = netip.MustParseAddrPort("203.0.113.1:1") // the caller's slice is not the runner's
	spec := e.spec(ref, "replicate")
	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:443"), netip.MustParseAddrPort("198.51.100.7:9000")}
	if !slices.Equal(spec.Addrs, want) || spec.Env["SUPAPACE_S3_ADDRS"] != "192.0.2.10:443,198.51.100.7:9000" {
		t.Fatalf("addrs %v, env %q", spec.Addrs, spec.Env["SUPAPACE_S3_ADDRS"])
	}
}

// ───────── recover ─────────

const recoverParamsJSON = `{"target":{"lsn":"0/5000000","timeline":"latest"}}`

// serveScript runs until stopped, then leaves sv as its result; it records
// its stop.
func (e *env) serveScript(sv *jobio.ServeResult) {
	e.ag.setScript("serve", func(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
		<-ctx.Done()
		e.ag.call("serve stopped")
		if sv == nil {
			return agent.JobResult{}, nil
		}
		return agent.JobResult{Result: line(*sv)}, nil
	})
}

func (e *env) recoverJob() (ref string, id int64) {
	ref = e.project("restoring")
	_, id = e.parked(ref, "recover", recoverParamsJSON)
	picked := make(chan bool, 1)
	go func() { picked <- e.turn("backup") }()
	select {
	case ok := <-picked:
		if !ok {
			e.t.Fatal("the recover job was not picked")
		}
	case <-time.After(30 * time.Second):
		e.t.Fatal("the recover job did not end within 30 s: its serve job or its recovery poll never stopped")
	}
	return ref, id
}

// bounded is a context for a call that must return well within 30 s.
func bounded(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestRecover_PromotedStopsServe(t *testing.T) {
	e := newEnv(t)
	e.serveScript(&jobio.ServeResult{OK: true, None: []string{}, LastSegment: "000000020000000000000009"})
	e.ag.state = func(n int) (bool, bool, error) { return n >= 3, false, nil }
	ref, id := e.recoverJob()
	got := e.job(id)
	if got.State != "done" {
		t.Fatalf("job = %+v", got)
	}
	calls := e.ag.called()
	if !slices.Contains(calls, "serve stopped") || slices.Contains(calls, "StopCluster "+ref) {
		t.Fatalf("calls %q: the serve job must be stopped and the promoted cluster kept", calls)
	}
	if !slices.Contains(calls, "EnsureRecovery "+ref+" 0/5000000") {
		t.Fatalf("calls %q: the recovery must start with the job's target", calls)
	}
}

func TestRecoverJob_StoppedServeResultReachesTheShortfallCheck(t *testing.T) {
	e := newEnv(t)
	e.serveScript(&jobio.ServeResult{OK: true, Served: 4, None: []string{"000000020000000000000010"}, LastSegment: "000000020000000000000009"})
	e.ag.state = func(n int) (bool, bool, error) { return n >= 2, false, nil }
	_, id := e.recoverJob()
	var rr jobio.RecoverResult
	must(t, json.Unmarshal(e.job(id).Result, &rr))
	if !rr.OK || !rr.Promoted || rr.Serve == nil || rr.Serve.LastSegment != "000000020000000000000009" || rr.Serve.Served != 4 {
		t.Fatalf("stored result %s", e.job(id).Result)
	}
}

func TestRecoverJob_ServeWithoutAResultIsKeptAsNull(t *testing.T) {
	e := newEnv(t)
	e.serveScript(nil)
	_, id := e.recoverJob()
	got := e.job(id)
	if got.State != "done" || !strings.Contains(string(got.Result), `"serve": null`) && !strings.Contains(string(got.Result), `"serve":null`) {
		t.Fatalf("job = %+v %s, want done with serve null", got, got.Result)
	}
}

func TestRecover_ExitedIsFailure(t *testing.T) {
	e := newEnv(t)
	e.serveScript(&jobio.ServeResult{OK: true, None: []string{}})
	e.ag.state = func(n int) (bool, bool, error) { return false, n >= 2, nil }
	ref, id := e.recoverJob()
	if got := e.job(id); got.State != "failed" || got.Code != "recovery_failed" {
		t.Fatalf("job = %+v", got)
	}
	if !slices.Contains(e.ag.called(), "StopCluster "+ref) {
		t.Fatalf("calls %q", e.ag.called())
	}
}

func TestRecover_LastNoneIsTargetNotReached(t *testing.T) {
	e := newEnv(t)
	e.serveScript(&jobio.ServeResult{OK: true, None: []string{"000000010000000000000009"}, Last: "000000010000000000000009", LastNone: true})
	e.ag.state = func(n int) (bool, bool, error) { return false, true, nil }
	_, id := e.recoverJob()
	if got := e.job(id); got.Code != "target_not_reached" {
		t.Fatalf("job = %+v, want target_not_reached", got)
	}
}

func TestRecover_Deadline(t *testing.T) {
	e := newEnv(t)
	e.serveScript(&jobio.ServeResult{OK: true, None: []string{}})
	e.ag.state = func(n int) (bool, bool, error) {
		if n == 3 {
			e.clock.Add(599 * time.Second) // the job's deadline is 600 s: not yet
		}
		if n == 5 {
			e.clock.Add(time.Second)
		}
		return false, false, nil
	}
	_, id := e.recoverJob()
	if got := e.job(id); got.Code != "deadline" {
		t.Fatalf("job = %+v, want deadline", got)
	}
	if e.ag.polls != 5 {
		t.Fatalf("%d polls: the deadline must end the job at the first poll at or past it", e.ag.polls)
	}
}

func TestRecoverJob_DeadlineRemovesRecoveryContainer(t *testing.T) {
	e := newEnv(t)
	e.serveScript(&jobio.ServeResult{OK: true, None: []string{}})
	e.ag.state = func(n int) (bool, bool, error) { e.clock.Add(time.Hour); return false, false, nil }
	ref, id := e.recoverJob()
	calls := e.ag.called()
	stop, serve := slices.Index(calls, "StopCluster "+ref), slices.Index(calls, "serve stopped")
	if e.job(id).Code != "deadline" || stop < 0 || serve < 0 || serve > stop {
		t.Fatalf("calls %q: the serve job stops, then the recovery cluster is removed", calls)
	}
}

func TestRecoverJob_EveryFailureStopsServeAndRecovery(t *testing.T) {
	cases := map[string]func(e *env){
		"start refused": func(e *env) { e.ag.ensureErr = errTest },
		"state error":   func(e *env) { e.ag.state = func(int) (bool, bool, error) { return false, false, errTest } },
		"exited":        func(e *env) { e.ag.state = func(int) (bool, bool, error) { return false, true, nil } },
		"deadline": func(e *env) {
			e.ag.state = func(int) (bool, bool, error) { e.clock.Add(time.Hour); return false, false, nil }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.serveScript(&jobio.ServeResult{OK: true, None: []string{}})
			setup(e)
			ref, id := e.recoverJob()
			calls := e.ag.called()
			if e.job(id).State != "failed" || !slices.Contains(calls, "StopCluster "+ref) {
				t.Fatalf("job %+v, calls %q", e.job(id), calls)
			}
			if slices.ContainsFunc(calls, func(c string) bool { return c == "RunJob "+ref+" serve" }) && !slices.Contains(calls, "serve stopped") {
				t.Fatalf("calls %q: the serve job was left running", calls)
			}
		})
	}
	t.Run("cancelled", func(t *testing.T) {
		e := newEnv(t)
		e.serveScript(&jobio.ServeResult{OK: true, None: []string{}})
		e.ag.state = func(int) (bool, bool, error) { return false, false, nil }
		ref := e.project("restoring")
		op, id := e.parked(ref, "recover", recoverParamsJSON)
		go e.turn("backup")
		e.ag.waitStart(t)
		_, err := e.db.Exec(context.Background(), "update operation set state = 'aborting' where id = $1", op)
		must(t, err)
		must(t, e.r.Cancel(bounded(t), op))
		calls := e.ag.called()
		if e.job(id).Code != "cancelled" || !slices.Contains(calls, "StopCluster "+ref) || !slices.Contains(calls, "serve stopped") {
			t.Fatalf("job %+v, calls %q", e.job(id), calls)
		}
	})
}

// ───────── the seam ─────────

// withSeams assigns the four function variables for the test (nil builders
// and recorders stay nil when not given) and restores them afterwards.
func withSeams(t *testing.T, build func(ctx context.Context, r *Runner, j store.Job, in *jobio.Input, spec *agent.JobSpec) error,
	rec func(store.Job, any) (json.RawMessage, error)) {
	t.Helper()
	b1, b2, r1, r2 := buildReplicate, buildFetch, recordReplicate, recordFetch
	t.Cleanup(func() { buildReplicate, buildFetch, recordReplicate, recordFetch = b1, b2, r1, r2 })
	if build == nil {
		build = func(context.Context, *Runner, store.Job, *jobio.Input, *agent.JobSpec) error { return nil }
	}
	buildReplicate, buildFetch = build, build
	if rec != nil {
		recordReplicate = func(_ context.Context, _ *Runner, j store.Job, v jobio.ReplResult) (json.RawMessage, error) {
			return rec(j, v)
		}
		recordFetch = func(_ context.Context, _ *Runner, j store.Job, v jobio.FetchResult) (json.RawMessage, error) {
			return rec(j, v)
		}
	}
}

func TestSeam_ReplicateAndFetchEndInternalWhileTheirFunctionsAreNil(t *testing.T) {
	e := newEnv(t)
	b1, b2, r1, r2 := buildReplicate, buildFetch, recordReplicate, recordFetch
	t.Cleanup(func() { buildReplicate, buildFetch, recordReplicate, recordFetch = b1, b2, r1, r2 })
	buildReplicate, buildFetch, recordReplicate, recordFetch = nil, nil, nil, nil
	e.declare()
	ref := e.project("active")
	repl := e.submit(ref, "replicate")
	e.turn("push")
	_, fetch := e.parked(e.project("restoring"), "fetch", `{}`)
	e.turn("backup")
	for _, id := range []int64{repl, fetch} {
		if got := e.job(id); got.State != "failed" || got.Code != "internal" {
			t.Fatalf("job %d = %+v, want failed/internal", id, got)
		}
	}
	if len(e.ag.specs) != 0 {
		t.Fatalf("launched %v", e.ag.specs)
	}
	// With builders but no recorders the job runs and ends internal too.
	withSeams(t, nil, nil)
	id := e.submit(ref, "replicate")
	e.turn("push")
	if got := e.job(id); got.Code != "internal" || len(e.ag.specs) != 1 {
		t.Fatalf("job = %+v, launches %d", got, len(e.ag.specs))
	}
}

func TestSeam_ALaterFileFillsTheFourVariables(t *testing.T) {
	e := newEnv(t)
	e.declare()
	var built, recorded []string
	withSeams(t, func(_ context.Context, _ *Runner, j store.Job, in *jobio.Input, spec *agent.JobSpec) error {
		built = append(built, j.Kind)
		spec.MemMB = 300
		if j.Kind == "replicate" {
			in.Repl = &jobio.ReplInput{Mode: "copy"}
		}
		return nil
	}, func(j store.Job, v any) (json.RawMessage, error) {
		recorded = append(recorded, j.Kind)
		return json.RawMessage(`{"ok":true,"by":"recorder"}`), nil
	})
	ref := e.project("active")
	repl := e.submit(ref, "replicate")
	e.turn("push")
	_, fetch := e.parked(e.project("restoring"), "fetch", `{}`)
	e.turn("backup")
	if !slices.Equal(built, []string{"replicate", "fetch"}) || !slices.Equal(recorded, []string{"replicate", "fetch"}) {
		t.Fatalf("built %q, recorded %q", built, recorded)
	}
	for _, id := range []int64{repl, fetch} {
		if got := e.job(id); got.State != "done" || !strings.Contains(string(got.Result), "recorder") {
			t.Fatalf("job %d = %+v %s", id, got, got.Result)
		}
	}
	if e.ag.specs[0].MemMB != 300 || !strings.Contains(string(e.ag.specs[0].Input), `"mode":"copy"`) {
		t.Fatalf("the builder's spec and input were not launched: %v %s", e.ag.specs[0].MemMB, e.ag.specs[0].Input)
	}
}

func TestSeam_RecordingVariablesAreHandedTheJobRow(t *testing.T) {
	e := newEnv(t)
	e.declare()
	var rows []store.Job
	withSeams(t, nil, func(j store.Job, _ any) (json.RawMessage, error) {
		rows = append(rows, j)
		return json.RawMessage(`{"ok":true}`), nil
	})
	ref := e.project("active")
	id := e.submit(ref, "replicate")
	e.turn("push")
	if len(rows) != 1 || rows[0].ID != id || rows[0].Subject != ref || rows[0].Kind != "replicate" || rows[0].State != "running" || rows[0].DeadlineS != 600 {
		t.Fatalf("rows %+v", rows)
	}
}
