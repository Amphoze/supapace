package backup

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/jobio"
)

// A running job that ends without this process's lane (here: recorded
// directly) between Cancel's read and its wait is not waited on, and leaves
// no entry behind.
func TestStop_JobEndedElsewhereIsNotWaitedOn(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	id := e.submit(ref, "check")
	if _, ok, err := e.st.NextJob(context.Background(), "backup"); !ok || err != nil {
		t.Fatal("no pick")
	}
	done := make(chan error, 1)
	go func() { done <- e.r.CancelSubject(bounded(t), ref) }()
	e.eventually("the stop to be registered", func() bool {
		e.r.mu.Lock()
		defer e.r.mu.Unlock()
		return e.r.active[id] != nil
	})
	must(t, e.st.FinishJob(context.Background(), id, "done", "", "", nil))
	if err := <-done; err != nil {
		t.Fatalf("CancelSubject: %v", err)
	}
	e.r.mu.Lock()
	n := len(e.r.active)
	e.r.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d entries left", n)
	}
}

// Job parameters are read strictly: member names exact and unique, nothing
// unknown, the required ones present. Anything else ends the job internal
// with nothing launched.
func TestJobSpec_ParamsDecodedStrictly(t *testing.T) {
	bad := map[string]string{
		"restore case":      `{"Set":"20261118-104332F","mode":"none"}`,
		"restore unknown":   `{"set":"20261118-104332F","mode":"none","extra":1}`,
		"restore no mode":   `{"set":"20261118-104332F"}`,
		"restore bad mode":  `{"set":"20261118-104332F","mode":"immediate"}`,
		"restore no target": `{"set":"20261118-104332F","mode":"standby"}`,
		"restore bad set":   `{"set":"latest","mode":"none"}`,
		"none with target":  `{"set":"20261118-104332F","mode":"none","target_timeline":2}`,
	}
	for name, p := range bad {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			_, id := e.parked(e.project("restoring"), "restore", p)
			e.turn("backup")
			if got := e.job(id); got.Code != "internal" || len(e.ag.specs) != 0 {
				t.Fatalf("job %+v, launches %d", got, len(e.ag.specs))
			}
		})
	}
	for name, p := range map[string]string{
		"recover go names":    `{"target":{"LSN":"0/5000000","Timeline":"latest"}}`,
		"recover no target":   `{}`,
		"recover unknown":     `{"target":{"lsn":"0/5000000","timeline":"latest","name":"x"}}`,
		"recover no timeline": `{"target":{"lsn":"0/5000000"}}`,
		"recover bad lsn":     `{"target":{"lsn":"0/50000;x","timeline":"latest"}}`,
		"recover null target": `{"target":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			_, id := e.parked(e.project("restoring"), "recover", p)
			e.turn("backup")
			if got := e.job(id); got.Code != "internal" || slices.ContainsFunc(e.ag.called(), func(c string) bool { return strings.HasPrefix(c, "EnsureRecovery") }) {
				t.Fatalf("job %+v, calls %q", got, e.ag.called())
			}
		})
	}
	t.Run("controls", func(t *testing.T) {
		e := newEnv(t)
		_, id := e.parked(e.project("restoring"), "restore", `{"set":"20261118-104332F","mode":"standby","target_timeline":2}`)
		e.turn("backup")
		_, id2 := e.parked(e.project("restoring"), "restore", `{"set":"20261118-104332F","mode":"none"}`)
		e.turn("backup")
		if e.job(id).State != "done" || e.job(id2).State != "done" {
			t.Fatalf("valid restores: %+v %+v", e.job(id), e.job(id2))
		}
		e.serveScript(&jobio.ServeResult{OK: true, None: []string{}})
		ref := e.project("restoring")
		_, id3 := e.parked(ref, "recover", `{"target":{"time":"2026-11-18T10:00:00Z","timeline":"2"}}`)
		e.turn("backup")
		if e.job(id3).State != "done" || !slices.Contains(e.ag.called(), "EnsureRecovery "+ref+" ") || !e.ag.target.Time.Equal(time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)) || e.ag.target.Timeline != "2" {
			t.Fatalf("valid recover: %+v, target %+v", e.job(id3), e.ag.target)
		}
	})
}

// A serve result whose names are out of shape is kept as no result.
func TestRecoverJob_ServeResultOutOfShapeIsKeptAsNull(t *testing.T) {
	for name, sv := range map[string]jobio.ServeResult{
		"last segment":   {OK: true, None: []string{}, LastSegment: "x\x1b"},
		"last":           {OK: true, None: []string{}, Last: strings.Repeat("A", 4096)},
		"none name":      {OK: true, None: []string{"../etc"}},
		"negative count": {OK: true, None: []string{}, Served: -1},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.serveScript(&sv)
			_, id := e.recoverJob()
			if got := e.job(id); got.State != "done" || !strings.Contains(string(got.Result), `"serve": null`) {
				t.Fatalf("job %+v %s", got, got.Result)
			}
		})
	}
}

// A serve job that exits non-zero leaves no result for the shortfall check.
func TestRecoverJob_ServeExitNonZeroIsKeptAsNull(t *testing.T) {
	e := newEnv(t)
	e.ag.setScript("serve", func(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
		<-ctx.Done()
		return agent.JobResult{ExitCode: 1, Result: okLine("serve")}, nil
	})
	_, id := e.recoverJob()
	if got := e.job(id); got.State != "done" || !strings.Contains(string(got.Result), `"serve": null`) {
		t.Fatalf("job %+v %s", got, got.Result)
	}
}

// At the deadline the code is deadline, also when the serve job's last
// answer was "none".
func TestRecover_DeadlineWithLastNoneIsDeadline(t *testing.T) {
	e := newEnv(t)
	e.serveScript(&jobio.ServeResult{OK: true, None: []string{"000000010000000000000009"}, Last: "000000010000000000000009", LastNone: true})
	e.ag.state = func(int) (bool, bool, error) { e.clock.Add(time.Hour); return false, false, nil }
	_, id := e.recoverJob()
	if got := e.job(id); got.Code != "deadline" {
		t.Fatalf("job %+v", got)
	}
}

// The job spec carries what each kind's input and the declaration say.
func TestJobSpec_KindMembersAndDeclaration(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	d := e.declare()
	d.CAPEM, d.PathStyle = "-----BEGIN CERTIFICATE-----\n", false
	e.r.SetOffsite(d, "declared", nil)
	ref := e.project("active")
	r := e.spec(ref, "replicate")
	if string(r.Files["ca.pem"]) != d.CAPEM || r.Env["SUPAPACE_S3_PATH_STYLE"] != "0" || r.Env["SUPAPACE_S3_ENDPOINT"] != d.Endpoint || r.Env["SUPAPACE_S3_REGION"] != "r1" {
		t.Fatalf("replicate files %q env %v", r.Files, r.Env)
	}
	d.PathStyle = true
	e.r.SetOffsite(d, "declared", nil)
	if e.spec(ref, "fetch").Env["SUPAPACE_S3_PATH_STYLE"] != "1" {
		t.Fatal("path style")
	}
	if in, _ := jobio.ParseInput(e.spec(ref, "serve").Input); in.MaxAnswers != 8 {
		t.Fatalf("serve input %+v", in)
	}
	if in, _ := jobio.ParseInput(e.spec(ref, "backup").Input); in.Type != "full" {
		t.Fatalf("backup input %+v", in)
	}
}

func TestRecord_FailedBackupRaisesItsNotice(t *testing.T) {
	e := newEnv(t)
	got := e.runWith("backup", agent.JobResult{ExitCode: 1, Result: failLine("archive_timeout", "x")}, nil)
	if got.Code != "archive_timeout" || e.count("select count(*) from backup_notice where code = 'backup-failed'") != 1 {
		t.Fatalf("job %+v", got)
	}
	if e.runWith("check", agent.JobResult{ExitCode: 1, Result: failLine("login", "x")}, nil); e.count("select count(*) from backup_notice where code = 'backup-failed'") != 1 {
		t.Fatal("a failed check raised backup-failed")
	}
}

func TestRun_ExitTwoWithAnOkDocumentIsCrashed(t *testing.T) {
	e := newEnv(t)
	if got := e.runWith("check", agent.JobResult{ExitCode: 2, Result: okLine("check")}, nil); got.Code != "crashed" {
		t.Fatalf("job %+v", got)
	}
}

func TestRun_TimedOutWithAResultIsDeadline(t *testing.T) {
	e := newEnv(t)
	if got := e.runWith("check", agent.JobResult{TimedOut: true, Result: okLine("check")}, nil); got.Code != "deadline" {
		t.Fatalf("job %+v", got)
	}
}

// failingQuota makes QuotaUse fail.
type failingQuota struct{ *fakeAgent }

func (failingQuota) QuotaUse(context.Context, int) (agent.QuotaUse, error) {
	return agent.QuotaUse{}, errTest
}

func TestRecord_PushWithoutQuotaUseIsStillRecorded(t *testing.T) {
	e := newEnv(t)
	e.r.ag = failingQuota{e.ag}
	ref := e.project("active")
	got := e.push(ref, agent.JobResult{Result: line(okPush())})
	if bs := e.state(ref); got.State != "done" || bs.SpoolEntries == nil || bs.QuotaAt != nil {
		t.Fatalf("job %+v, state %+v", got, bs)
	}
}

func TestHourly_ControlPlaneDiskHalfAndNoRowNoRead(t *testing.T) {
	e := newEnv(t)
	e.hourly()
	if slices.Contains(e.ag.called(), "QuotaUse 70") {
		t.Fatal("the control plane's quota was read with no backup state")
	}
	e.controlPlane()
	e.ag.quota = agent.QuotaUse{DiskUsedKB: 32768 * 512}
	e.hourly()
	if e.notices("cp", "cp-quota-half") != 1 {
		t.Fatal("no notice at half the data quota")
	}
}

func TestHourly_UnadoptedProjectKeepsItsFetch(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.pr.setAdopted(ref, false)
	e.hourly()
	if slices.Contains(e.ag.called(), "RemoveFetch "+ref) {
		t.Fatal("RemoveFetch of a project not adopted here")
	}
}

func TestScheduler_FirstTickRunsTheHourlyWork(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	must(t, e.r.tickOnce(context.Background()))
	if !slices.Contains(e.ag.called(), "RemoveFetch "+ref) {
		t.Fatalf("calls %q", e.ag.called())
	}
}

// A job already stopped with a code keeps it when containment stops the rest.
func TestContainment_KeepsAnEarlierStopCode(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	e.declare()
	e.ag.setScript("replicate", blockUntilStopped)
	ref := e.project("active")
	id := e.submit(ref, "replicate")
	go e.turn("push")
	e.ag.waitStart(t)
	e.r.mu.Lock()
	e.r.active[id].code = "cancelled" // a cancel is under way
	e.r.mu.Unlock()
	e.ag.setContainment(true)
	e.r.lastHourly = e.clock.Now()
	must(t, e.r.tickOnce(context.Background()))
	e.r.mu.Lock()
	code := e.r.active[id].code
	e.r.mu.Unlock()
	if code != "cancelled" {
		t.Fatalf("code %q", code)
	}
}

var _ = errors.New

// The parameters column is jsonb, which keeps the last of two equal names
// before the runner reads it; the parser refuses a duplicate all the same.
func TestParams_DuplicateMemberRefused(t *testing.T) {
	if _, err := parseRestoreParams([]byte(`{"set":"20261118-104332F","mode":"none","mode":"none"}`)); err == nil {
		t.Fatal("restore duplicate accepted")
	}
	if _, err := parseRecoverParams([]byte(`{"target":{"timeline":"latest","timeline":"2"}}`)); err == nil {
		t.Fatal("recover duplicate accepted")
	}
	if _, err := parseRecoverParams([]byte(`{"target":{"timeline":"latest"}} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := parseRecoverParams([]byte(`{"target":{"timeline":"latest"}}`)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// Each history a push names is a history name; one other name is refused.
func TestRecord_PushHistoryOfAnotherShapeIsCrashed(t *testing.T) {
	for _, h := range []string{"000000010000000000000001", "00000002.HISTORY", "../00000002.history"} {
		e := newEnv(t)
		ref := e.project("active")
		p := okPush()
		p.Histories = []string{"00000002.history", h}
		if got := e.push(ref, agent.JobResult{Result: line(p)}); got.Code != "crashed" {
			t.Fatalf("%q: job %+v", h, got)
		}
	}
	e := newEnv(t)
	p := okPush()
	p.Histories = []string{"00000002.history"}
	if got := e.push(e.project("active"), agent.JobResult{Result: line(p)}); got.State != "done" {
		t.Fatalf("control: %+v", got)
	}
}

// A restore's mode and a seed's figures are checked before they are stored.
func TestRecord_RestoreModeAndSeedFiguresChecked(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		kind, params string
		res          any
		want         string
	}{
		{"restore", `{"set":"20261118-104332F","mode":"none"}`, jobio.RestoreResult{OK: true, Mode: "immediate"}, "crashed"},
		{"restore", `{"set":"20261118-104332F","mode":"none"}`, jobio.RestoreResult{OK: true, Mode: "standby"}, ""},
		{"seed", "", jobio.SeedResult{OK: true, Files: -1}, "crashed"},
		{"seed", "", jobio.SeedResult{OK: true, Bytes: -1}, "crashed"},
		{"seed", "", jobio.SeedResult{OK: true, Files: 1, Bytes: 1}, ""},
	} {
		e.ag.setScript(c.kind, func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{Result: line(c.res)}, nil
		})
		_, id := e.parked(e.project("restoring"), c.kind, c.params)
		e.turn("backup")
		if got := e.job(id); got.Code != c.want {
			t.Fatalf("%s %+v: code %q, want %q", c.kind, c.res, got.Code, c.want)
		}
	}
}

// A job whose row was ended elsewhere while it ran (a new epoch) is not
// recorded again: the lane's record stops at the conflict.
func TestRun_RecordOfAJobEndedElsewhereStops(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	release := make(chan struct{})
	e.ag.setScript("check", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		<-release
		return agent.JobResult{Result: okLine("check")}, nil
	})
	id := e.submit(ref, "check")
	ended := make(chan bool, 1)
	go func() { ended <- e.turn("backup") }()
	e.ag.waitStart(t)
	must(t, e.st.FinishJob(context.Background(), id, "failed", "recovered", "x", nil))
	close(release)
	select {
	case <-ended:
	case <-time.After(30 * time.Second):
		t.Fatal("the lane kept trying to record a job that is not running")
	}
	if got := e.job(id); got.Code != "recovered" {
		t.Fatalf("job %+v", got)
	}
}

// Every push figure is checked: the pushed count against the entry cap, the
// other counts and histories' number.
func TestRecord_PushFiguresChecked(t *testing.T) {
	hist := func(n int) []string {
		var h []string
		for i := range n {
			h = append(h, fmt.Sprintf("%08X.history", i+2))
		}
		return h
	}
	for name, c := range map[string]struct {
		bad  func(*jobio.PushResult)
		want string
	}{
		"pushed -1":    {func(p *jobio.PushResult) { p.Pushed = -1 }, "crashed"},
		"pushed 57":    {func(p *jobio.PushResult) { p.Pushed = 57 }, "crashed"},
		"pushed 56":    {func(p *jobio.PushResult) { p.Pushed = 56 }, ""},
		"remaining -1": {func(p *jobio.PushResult) { p.Remaining = -1 }, "crashed"},
		"other -1":     {func(p *jobio.PushResult) { p.OtherEntries = -1 }, "crashed"},
		"65 histories": {func(p *jobio.PushResult) { p.Histories = hist(65) }, "crashed"},
		"64 histories": {func(p *jobio.PushResult) { p.Histories = hist(64) }, ""},
		"255-byte name": {func(p *jobio.PushResult) {
			p.Quarantined = []jobio.Quarantined{{Name: strings.Repeat("n", 255), Reason: "shape"}}
		}, ""},
		"256-byte name": {func(p *jobio.PushResult) {
			p.Quarantined = []jobio.Quarantined{{Name: strings.Repeat("n", 256), Reason: "shape"}}
		}, "crashed"},
		"empty name": {func(p *jobio.PushResult) { p.Quarantined = []jobio.Quarantined{{Name: "", Reason: "shape"}} }, "crashed"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			p := okPush()
			c.bad(&p)
			if got := e.push(e.project("active"), agent.JobResult{Result: line(p)}); got.Code != c.want {
				t.Fatalf("code %q, want %q", got.Code, c.want)
			}
		})
	}
}
