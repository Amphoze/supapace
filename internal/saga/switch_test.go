package saga

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/store"
)

// layout1 is the configuration of a project created before backups.
var layout1 = store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{}, Layout: 1}

// activeWith creates a project with cfg and runs its create to done, with
// lanes that end every job done (a layout-2 create parks on jobs).
func (e *env) activeWith(cfg store.ProjectConfig) string {
	e.t.Helper()
	ref, id := e.create2(cfg)
	stop := e.start(e.runner())
	e.waitState(id, "done")
	stop()
	e.ag.reset()
	return ref
}

// to2 is cfg moved to layout 2, with a setting changed so that the restart
// has something to apply.
func to2(cfg store.ProjectConfig) store.ProjectConfig {
	cfg.Layout = 2
	cfg.GUC = map[string]string{"max_connections": "200"}
	return cfg
}

// spec is one agent call with its whole spec.
type specCall struct {
	method string
	s      agent.Spec
}

// spyAgent records the spec of the backup-path calls beside the fake's own
// record.
type spyAgent struct {
	*fakeAgent
	mu    sync.Mutex
	specs []specCall
	at    func(method string, s agent.Spec) // runs before the fake's effect
}

func (a *spyAgent) seen(method string, s agent.Spec) {
	a.mu.Lock()
	a.specs = append(a.specs, specCall{method, s})
	at := a.at
	a.mu.Unlock()
	if at != nil {
		at(method, s)
	}
}

func (a *spyAgent) EnsureSpoolDirs(ctx context.Context, s agent.Spec) error {
	a.seen("EnsureSpoolDirs", s)
	return a.fakeAgent.EnsureSpoolDirs(ctx, s)
}
func (a *spyAgent) EnsureRepoDir(ctx context.Context, s agent.Spec) error {
	a.seen("EnsureRepoDir", s)
	return a.fakeAgent.EnsureRepoDir(ctx, s)
}
func (a *spyAgent) EnsureCluster(ctx context.Context, s agent.Spec) error {
	a.seen("EnsureCluster", s)
	return a.fakeAgent.EnsureCluster(ctx, s)
}
func (a *spyAgent) GrantBackupRole(ctx context.Context, s agent.Spec) error {
	a.seen("GrantBackupRole", s)
	return a.fakeAgent.GrantBackupRole(ctx, s)
}
func (a *spyAgent) PurgeDir(ctx context.Context, s agent.Spec) error {
	a.seen("PurgeDir", s)
	return a.fakeAgent.PurgeDir(ctx, s)
}
func (a *spyAgent) PurgeRepo(ctx context.Context, s agent.Spec) error {
	a.seen("PurgeRepo", s)
	return a.fakeAgent.PurgeRepo(ctx, s)
}

func (a *spyAgent) of(method string) []agent.Spec {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []agent.Spec
	for _, c := range a.specs {
		if c.method == method {
			out = append(out, c.s)
		}
	}
	return out
}

// spyRunner is a test runner whose agent is a spy over the env's fake.
func (e *env) spyRunner() (*Runner, *spyAgent) {
	a := &spyAgent{fakeAgent: e.ag}
	r := e.runner()
	r.ag = a
	return r, a
}

// pushJobs is the fake job runner with PushNow's outcome and error chosen
// by the test, and the wait it was asked for recorded.
type pushJobs struct {
	*fakeJobs
	outcome string
	err     error
	waits   []time.Duration
	mu      sync.Mutex
}

func (j *pushJobs) PushNow(ctx context.Context, subject string, wait time.Duration) (string, error) {
	if _, err := j.fakeJobs.PushNow(ctx, subject, wait); err != nil {
		return "", err
	}
	j.mu.Lock()
	j.waits = append(j.waits, wait)
	j.mu.Unlock()
	return j.outcome, j.err
}

// recordSets makes a done backup job record a set, as the runner does.
func (e *env) recordSets(j store.Job) {
	if j.Kind != "backup" {
		return
	}
	if err := e.st.RecordSet(context.Background(), store.BackupSet{Subject: j.Subject, Label: "20261118-104332F", TLI: 1,
		StartSegment: "000000010000000000000004", StopSegment: "000000010000000000000004", StartLSN: "0/4000028",
		StopLSN: "0/4000100", StartAt: time.Now(), StopAt: time.Now(), JobID: j.ID}); err != nil {
		e.t.Error(err)
	}
}

var switchSteps = []string{"R0", "R1", "S1", "R2", "R3", "R4", "R5", "S2", "S3", "S4", "S5", "S6"}

// ───────── R2's drain push ─────────

func TestRestart_Layout2_DrainAsksForPush_TimeoutContinues(t *testing.T) {
	for _, c := range []struct {
		outcome string
		err     error
		want    string
	}{{"timeout", nil, "timeout"}, {"ok", nil, "ok"}, {"incomplete", nil, "incomplete"}, {"", errBoom, "failed"}} {
		t.Run(c.want, func(t *testing.T) {
			e := newEnv(t)
			e.lanes(nil)
			ref := e.activeWith(layout2)
			pj := &pushJobs{fakeJobs: e.jobs, outcome: c.outcome, err: c.err}
			r := e.runner()
			r.SetJobs(pj)
			id := e.restart(r, ref, withGUC("max_connections", "200"))
			e.start(r)
			op := e.waitState(id, "done")
			if got := paramOf(op, "drain_push"); got != c.want {
				t.Fatalf("drain_push %q, want %q", got, c.want)
			}
			pj.mu.Lock()
			waits := slices.Clone(pj.waits)
			pj.mu.Unlock()
			if !slices.Equal(waits, []time.Duration{bklimit.DrainPushWait}) {
				t.Fatalf("waits %v", waits)
			}
			// The push is asked for after the route drains and before the
			// cluster stops.
			m := e.ag.methods(ref)
			i := slices.Index(m, "Jobs.PushNow")
			if i < 0 || i < slices.Index(m, "SetRoute") || i > slices.Index(m, "StopCluster") {
				t.Fatalf("calls %v", m)
			}
		})
	}
}

func TestRestart_DuringTheSwitchNoDrainPush(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout1)
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	op := e.waitState(id, "done")
	if n := len(e.ag.callsOf(ref, "Jobs.PushNow")); n != 0 || paramOf(op, "drain_push") != "" {
		t.Fatalf("%d drain pushes, params %s", n, op.Params)
	}
	// Control: the same project at layout 2 gets one.
	id = e.restart(r, ref, to2(withGUC("max_connections", "300")))
	op = e.waitState(id, "done")
	if n := len(e.ag.callsOf(ref, "Jobs.PushNow")); n != 1 || paramOf(op, "drain_push") != "ok" {
		t.Fatalf("%d drain pushes, params %s", n, op.Params)
	}
}

// ───────── the switch ─────────

func TestSwitch_StepOrder(t *testing.T) {
	e := newEnv(t)
	e.declared()
	e.lanes(nil)
	ref := e.activeWith(layout1)
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	e.waitState(id, "done")
	wantSeq(t, e.steps(id), switchSteps)
	wantSeq(t, e.ag.methods(ref), []string{"Prevalidate",
		"EnsureSpoolDirs", "EnsureRepoDir", // S1
		"SetRoute", "StopPostgREST",
		"StopCluster", "SetQuota", "PromoteCandidate", "EnsureCluster", "EnsureCluster", "VerifyCluster",
		"EnsurePostgREST", "SetRoute", "ProbeREST", // R5
		"GrantBackupRole"}) // S2
	wantSeq(t, e.jobSteps(id), []string{"S3/stanza-create", "S4/backup", "S5/check", "S6/replicate"})
	p := e.project(ref)
	if p.State != "active" || p.Config.Layout != 2 || p.Generation != 2 {
		t.Fatalf("project %+v", p)
	}
}

func TestSwitch_S1BeforeStart_TaskNotRoot(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout1)
	r, spy := e.spyRunner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	e.waitState(id, "done")
	m := e.ag.methods(ref)
	if i := slices.Index(m, "EnsureSpoolDirs"); i < 0 || i > slices.Index(m, "StopCluster") || i > slices.Index(m, "EnsureCluster") {
		t.Fatalf("calls %v", m)
	}
	uid := *e.project(ref).UID
	for _, method := range []string{"EnsureSpoolDirs", "EnsureRepoDir"} {
		ss := spy.of(method)
		if len(ss) != 1 || ss[0].UID != uid || uid == 0 || ss[0].GID != uid || ss[0].Layout != 2 || ss[0].Ref != ref {
			t.Fatalf("%s specs %+v (uid %d)", method, ss, uid)
		}
	}
}

func TestSwitch_S1EnsuresBackupState(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout1)
	ctx := context.Background()
	if _, err := e.st.GetBackupState(ctx, ref); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("backup state before the switch: %v", err)
	}
	r, spy := e.spyRunner()
	// Every start at layout 2 finds the records the layout needs.
	spy.at = func(method string, s agent.Spec) {
		if method == "EnsureCluster" && s.Layout == 2 {
			_, berr := e.st.GetBackupState(ctx, ref)
			var repo bool
			e.ag.locked(func() { repo = e.ag.repo[ref] })
			if berr != nil || !repo || s.Stanza != ref+"-1" || s.StanzaPass == "" {
				t.Errorf("layout-2 start without its records: state %v, repo %v, stanza %q, pass set %v", berr, repo, s.Stanza, s.StanzaPass != "")
			}
		}
	}
	id := e.restart(r, ref, to2(layout1))
	e.failpoint("restart:R3")
	<-e.run(r)
	if op := e.op(id); op.Step != "R2" {
		t.Fatalf("op %+v", op)
	}
	if _, err := e.st.GetBackupState(ctx, ref); err != nil {
		t.Fatal(err)
	}
	pass := e.secret(ref, stanzaPassName)
	e.start(r)
	e.waitState(id, "done")
	if len(spy.of("EnsureCluster")) == 0 {
		t.Fatal("no start")
	}
	// A later restart keeps the passphrase.
	id = e.restart(r, ref, to2(withGUC("max_connections", "300")))
	e.waitState(id, "done")
	if e.secret(ref, stanzaPassName) != pass || len(pass) < 32 {
		t.Fatal("the stanza passphrase was replaced")
	}
}

func TestSwitch_ResumesBeforeGrantAndBackup(t *testing.T) {
	e := newEnv(t)
	ref := e.activeWith(layout1)
	var bad atomic.Value
	bad.Store("")
	var seen atomic.Int32
	served := func(when string) {
		seen.Add(1)
		p, err := e.st.GetProject(context.Background(), ref)
		var route string
		e.ag.locked(func() { route = e.ag.route[ref].State })
		if err != nil || p.State != "active" || route != "active" {
			bad.Store(when + ": " + p.State + "/" + route)
		}
	}
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "GrantBackupRole" {
			served("grant")
		}
	})
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	// Each job of the switch is submitted while the project is served.
	e.start(r)
	for _, step := range []string{"S3", "S4", "S5"} {
		e.wait(id, "parked at "+step, func(op store.Operation) bool {
			jobs := e.jobsOf(id)
			return op.State == "waiting_job" && len(jobs) > 0 && jobs[len(jobs)-1].OpStep == step
		})
		served(step)
		j, ok, err := e.st.NextJob(context.Background(), "backup")
		if err != nil || !ok {
			t.Fatalf("job of %s: %v %v", step, ok, err)
		}
		if step == "S3" {
			must(t, e.st.MarkStanza(context.Background(), ref))
		}
		must(t, e.st.FinishJob(context.Background(), j.ID, "done", "", "", json.RawMessage(`{"ok":true}`)))
	}
	e.waitState(id, "done")
	if s := bad.Load().(string); s != "" || seen.Load() != 4 || len(e.ag.callsOf(ref, "GrantBackupRole")) != 1 {
		t.Fatalf("not served at %q (%d checks)", s, seen.Load())
	}
}

func TestSwitch_FailingGrantLeavesTheProjectServing(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout1)
	e.ag.setErr(failOn("GrantBackupRole"))
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	op := e.waitState(id, "failed")
	if op.Step != "R5" || strings.Contains(op.LastError, "stays restarting") || len(e.jobsOf(id)) != 0 {
		t.Fatalf("op %+v, jobs %v", op, e.jobSteps(id))
	}
	p := e.project(ref)
	e.ag.locked(func() {
		if p.State != "active" || p.AppliedGen != 2 || p.Config.Layout != 2 || e.ag.route[ref].State != "active" {
			t.Fatalf("project %+v, route %+v", p, e.ag.route[ref])
		}
	})
}

func TestSwitch_HealthFailureRollsForwardToLayout1(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout1)
	failVerifyAt(e, 2)
	r, spy := e.spyRunner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	op := e.waitState(id, "aborted")
	p := e.project(ref)
	if p.State != "active" || p.Generation != 3 || p.Config.Layout != 1 || paramOf(op, "first_backup") != "" {
		t.Fatalf("project %+v, op %+v", p, op)
	}
	var layouts []int
	for _, s := range spy.of("EnsureCluster") {
		layouts = append(layouts, s.Layout)
	}
	if !slices.Equal(layouts, []int{2, 2, 1, 1}) {
		t.Fatalf("start layouts %v", layouts)
	}
	// The S steps do nothing on the rollback: no grant, no job, no second S1.
	if len(e.jobsOf(id)) != 0 || len(e.ag.callsOf(ref, "GrantBackupRole")) != 0 || len(e.ag.callsOf(ref, "EnsureSpoolDirs")) != 1 {
		t.Fatalf("jobs %v, calls %v", e.jobSteps(id), e.ag.methods(ref))
	}
	wantSeq(t, e.steps(id), []string{"R0", "R1", "S1", "R2", "R3", "R1", "R2", "R3", "R4", "R5"})
}

// A switch rolled back to layout 1 leaves its spool and repository trees;
// the purge removes them like any other.
func TestSwitch_RolledBackProjectIsPurged(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout1)
	failVerifyAt(e, 2)
	r, spy := e.spyRunner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	e.waitState(id, "aborted")
	e.ag.setErr(nil)
	_, purge := e.deleted(r, ref)
	e.waitState(purge, "done")
	if p := e.project(ref); p.State != "purged" {
		t.Fatalf("project %+v", p)
	}
	for _, m := range []string{"PurgeDir", "PurgeRepo"} {
		if ss := spy.of(m); len(ss) != 1 || ss[0].Layout != 1 || ss[0].UID != *e.project(ref).UID {
			t.Fatalf("%s specs %+v", m, ss)
		}
	}
	e.ag.locked(func() {
		if e.ag.repo[ref] || e.ag.effects["purgerepo "+ref] != 1 {
			t.Fatalf("repository kept: %v", e.ag.effects)
		}
	})
	bs, err := e.st.GetBackupState(context.Background(), ref)
	if err != nil || !bs.OffsitePurge {
		t.Fatalf("backup state %+v, %v", bs, err)
	}
}

func TestSwitch_CompletedByALaterRestart(t *testing.T) {
	e := newEnv(t)
	var fail atomic.Bool
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "backup" && fail.Load() {
			return jobEnd{state: "failed", code: "pgbackrest", msg: "backup failed"}
		}
		return okEnd
	})
	ref := e.activeWith(layout1)
	fail.Store(true)
	r := e.runner()
	first := e.restart(r, ref, to2(layout1))
	e.start(r)
	op := e.waitState(first, "failed")
	if op.Step != "S3" {
		t.Fatalf("first switch %+v", op)
	}
	if p := e.project(ref); p.State != "active" || p.Config.Layout != 2 {
		t.Fatalf("project %+v", p)
	}
	fail.Store(false)
	e.ag.reset()
	next := e.restart(r, ref, to2(withGUC("max_connections", "300")))
	op = e.waitState(next, "done")
	wantSeq(t, e.steps(next), switchSteps)
	// The stanza exists: S3 has no job; S6 has none while the store is undeclared.
	wantSeq(t, e.jobSteps(next), []string{"S4/backup", "S5/check"})
	if len(e.ag.callsOf(ref, "GrantBackupRole")) != 1 || paramOf(op, "first_backup") != "true" {
		t.Fatalf("calls %v, params %s", e.ag.methods(ref), op.Params)
	}
}

func TestSwitch_OpRetrySubmitsFreshJobs(t *testing.T) {
	e := newEnv(t)
	var fail atomic.Bool
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "check" && fail.Load() {
			return jobEnd{state: "failed", code: "pgbackrest", msg: "check failed"}
		}
		return okEnd
	})
	ref := e.activeWith(layout1)
	fail.Store(true)
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	op := e.waitState(id, "failed")
	if op.Step != "S4" {
		t.Fatalf("op %+v", op)
	}
	old := e.jobsOf(id)
	fail.Store(false)
	must(t, e.st.RetryOperation(context.Background(), id))
	e.waitState(id, "done")
	fresh := e.jobsOf(id)[len(old):]
	if len(fresh) != 1 || fresh[0].OpStep != "S5" || fresh[0].State != "done" || fresh[0].ID <= old[len(old)-1].ID {
		t.Fatalf("after the retry %+v", fresh)
	}
	if p := e.project(ref); p.State != "active" || p.Generation != 2 {
		t.Fatalf("project %+v", p)
	}
}

func TestSwitch_NotRepeatedOnceASetExists(t *testing.T) {
	e := newEnv(t)
	e.lanes(func(j store.Job) jobEnd {
		e.recordSets(j)
		return okEnd
	})
	ref := e.activeWith(layout1)
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	e.waitState(id, "done")
	e.ag.reset()
	next := e.restart(r, ref, to2(withGUC("max_connections", "300")))
	op := e.waitState(next, "done")
	if len(e.jobsOf(next)) != 0 || len(e.ag.callsOf(ref, "GrantBackupRole")) != 0 || paramOf(op, "first_backup") != "false" {
		t.Fatalf("jobs %v, calls %v, params %s", e.jobSteps(next), e.ag.methods(ref), op.Params)
	}
	wantSeq(t, e.steps(next), switchSteps)
}

func TestRestart_ResumeAfterR5DoesNotRepeatR3(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout1)
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	e.failpoint("restart:S2")
	<-e.run(r)
	if op := e.op(id); op.Step != "R5" || op.State != "running" {
		t.Fatalf("op %+v", op)
	}
	e.ag.reset()
	e.start(e.runner())
	e.waitState(id, "done")
	for _, m := range []string{"StopCluster", "EnsureCluster", "PromoteCandidate", "SetQuota"} {
		if n := len(e.ag.callsOf(ref, m)); n != 0 {
			t.Fatalf("%s called %d times after the resume: %v", m, n, e.ag.methods(ref))
		}
	}
	wantSeq(t, e.jobSteps(id), []string{"S3/stanza-create", "S4/backup", "S5/check"})
}

func TestSameConfig_ComparesNewFields(t *testing.T) {
	base := store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{"a": "1"}, Layout: 2,
		UploadMBPerDay: 10, UploadObjectsPerDay: 20, IO: &store.IOLimits{ReadBPS: 1, WriteBPS: 2, ReadIOPS: 3, WriteIOPS: 4}}
	same := base
	same.GUC = map[string]string{"a": "1"}
	same = withIO(same, &store.IOLimits{ReadBPS: 1, WriteBPS: 2, ReadIOPS: 3, WriteIOPS: 4})
	if !sameConfig(base, same) {
		t.Fatal("equal configurations differ")
	}
	nilGUC := base
	nilGUC.GUC = nil
	empty := base
	empty.GUC = map[string]string{}
	if !sameConfig(nilGUC, empty) {
		t.Fatal("a nil and an empty GUC map differ")
	}
	for name, change := range map[string]func(*store.ProjectConfig){
		"layout":      func(c *store.ProjectConfig) { c.Layout = 1 },
		"upload MB":   func(c *store.ProjectConfig) { c.UploadMBPerDay = 11 },
		"upload objs": func(c *store.ProjectConfig) { c.UploadObjectsPerDay = 21 },
		"quota":       func(c *store.ProjectConfig) { c.DiskQuotaMB = 1 },
		"memory":      func(c *store.ProjectConfig) { c.MemMB = 1 },
		"guc":         func(c *store.ProjectConfig) { c.GUC = map[string]string{"a": "2"} },
		"outbound":    func(c *store.ProjectConfig) { c.Outbound = true },
		"image":       func(c *store.ProjectConfig) { c.Image = "x" },
		"version":     func(c *store.ProjectConfig) { c.ImageVersion = "x" },
		"io":          func(c *store.ProjectConfig) { *c = withIO(*c, &store.IOLimits{ReadBPS: 9}) },
		"io nil":      func(c *store.ProjectConfig) { *c = withIO(*c, nil) },
	} {
		c := base
		c.GUC = map[string]string{"a": "1"}
		change(&c)
		if sameConfig(base, c) || sameConfig(c, base) {
			t.Errorf("%s: a changed configuration compares equal", name)
		}
	}
}

// ───────── the parameters across a roll-forward ─────────

// Every member a step or the worker writes into a restart's parameters
// keeps its value when R3 or R4 rolls the restart forward.
func TestRestart_ParameterMembersSurviveEveryRewriteOfTheParameters(t *testing.T) {
	members := map[string]string{
		"job_floor":    `7`,
		"first_backup": `true`,
		"drain_push":   `"timeout"`,
		"repl_free":    `{"step":"S6","floor":7,"last":9,"n":2}`,
		"requeued":     `1`,
		"cp_lsn":       `"0/1"`, // a member no restart step knows
	}
	for _, at := range []string{"R3", "R4"} {
		for name, v := range members {
			t.Run(at+"/"+name, func(t *testing.T) {
				e := newEnv(t)
				ref := e.active()
				if at == "R3" {
					e.ag.setErr(func(c call) error {
						if p, _ := e.st.GetProject(context.Background(), ref); c.Method == "PromoteCandidate" && p.Generation == 2 {
							return errBoom
						}
						return nil
					})
				} else {
					failVerifyAt(e, 2)
				}
				r := e.runner()
				id := e.restart(r, ref, withGUC("max_connections", "200"))
				sql(t, "update operation set params = jsonb_set(params, $2, $3::jsonb) where id = $1", id, []string{name}, v)
				e.start(r)
				op := e.waitState(id, "aborted")
				var m map[string]json.RawMessage
				must(t, json.Unmarshal(op.Params, &m))
				var want, got any
				must(t, json.Unmarshal([]byte(v), &want))
				must(t, json.Unmarshal(m[name], &got))
				if !jsonEqual(want, got) || paramOf(op, "rollback_gen") != "3" {
					t.Fatalf("%s after the roll-forward from %s: %s", name, at, op.Params)
				}
				if _, has := m["rollback_step"]; has != (at == "R3") || at == "R3" && paramOf(op, "rollback_step") != "R3" {
					t.Fatalf("rollback_step %q: %s", paramOf(op, "rollback_step"), op.Params)
				}
			})
		}
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// A layout-2 restart whose R3 fails: the as-built rollback_step beside the
// members this phase writes.
func TestRestart_ParamsKeepRollbackStepBesideTheNewMembers(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout2)
	e.ag.setErr(func(c call) error {
		if p, _ := e.st.GetProject(context.Background(), ref); c.Method == "PromoteCandidate" && p.Generation == 2 {
			return errBoom
		}
		return nil
	})
	r := e.runner()
	id := e.restart(r, ref, to2(layout2))
	e.start(r)
	op := e.waitState(id, "aborted")
	if paramOf(op, "rollback_step") != "R3" || paramOf(op, "drain_push") != "ok" || paramOf(op, "rollback_gen") != "3" ||
		paramOf(op, "first_backup") != "false" {
		t.Fatalf("params %s", op.Params)
	}
	var rp restartParams
	must(t, json.Unmarshal(op.Params, &rp))
	if rp.Prev.Layout != 2 || rp.Next.Layout != 2 || rp.BaseGeneration != 1 {
		t.Fatalf("params %s", op.Params)
	}
}

// ───────── crashes ─────────

// A worker stopped before each step of a switch resumes it: the switch
// converges, each job is submitted once, and no cluster starts at layout 2
// without the records layout 2 needs.
func TestSwitch_FailpointsResume(t *testing.T) {
	for _, s := range switchSteps {
		t.Run(s, func(t *testing.T) {
			e := newEnv(t)
			e.declared()
			e.lanes(nil)
			ref := e.activeWith(layout1)
			r, spy := e.spyRunner()
			var missing atomic.Int32
			spy.at = func(method string, sp agent.Spec) {
				if method != "EnsureCluster" || sp.Layout != 2 {
					return
				}
				_, err := e.st.GetBackupState(context.Background(), ref)
				var repo bool
				e.ag.locked(func() { repo = e.ag.repo[ref] })
				if err != nil || !repo || sp.StanzaPass == "" || len(e.ag.callsOf(ref, "EnsureSpoolDirs")) == 0 {
					missing.Add(1)
				}
			}
			id := e.restart(r, ref, to2(layout1))
			e.failpoint("restart:" + s)
			<-e.run(r)
			if op := e.op(id); op.State != "running" {
				t.Fatalf("after the failpoint: %+v", op)
			}
			r2, spy2 := e.spyRunner()
			spy2.at = spy.at
			e.start(r2)
			e.waitState(id, "done")
			p := e.project(ref)
			if p.State != "active" || p.Generation != 2 || p.AppliedGen != 2 || p.Config.Layout != 2 || missing.Load() != 0 {
				t.Fatalf("project %+v, %d starts without records", p, missing.Load())
			}
			wantSeq(t, e.jobSteps(id), []string{"S3/stanza-create", "S4/backup", "S5/check", "S6/replicate"})
			e.ag.locked(func() {
				if e.ag.effects["repo "+ref] != 1 {
					t.Errorf("repository made %d times", e.ag.effects["repo "+ref])
				}
			})
		})
	}
}

// A worker that stops while the switch waits for its job, and a daemon
// restart that interrupts the job: the switch submits it again and ends.
func TestSwitch_CrashWhileParked(t *testing.T) {
	e := newEnv(t)
	ref := e.activeWith(layout1)
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	stop := e.start(r)
	op := e.waitState(id, "waiting_job")
	stop()
	if op.Step != "S2" {
		t.Fatalf("parked %+v", op)
	}
	// The job is running when the daemon stops; at its next start the job
	// is interrupted and the operation goes back to pending.
	ctx := context.Background()
	if _, ok, err := e.st.NextJob(ctx, "backup"); err != nil || !ok {
		t.Fatalf("pick: %v %v", ok, err)
	}
	if n, err := e.st.InterruptJobs(ctx); err != nil || n != 1 {
		t.Fatalf("interrupted %d: %v", n, err)
	}
	if op := e.op(id); op.State != "pending" || op.Step != "S2" {
		t.Fatalf("after the interruption %+v", op)
	}
	e.lanes(nil)
	e.start(e.runner())
	op = e.waitState(id, "done")
	if p := e.project(ref); p.State != "active" || p.Config.Layout != 2 || op.Attempts != 1 {
		t.Fatalf("project %+v, op %+v", p, op)
	}
	wantSeq(t, e.jobSteps(id), []string{"S3/stanza-create", "S3/stanza-create", "S4/backup", "S5/check"})
	if j := e.jobsOf(id)[0]; j.State != "failed" || j.Code != "interrupted" {
		t.Fatalf("first job %+v", j)
	}
}

// ───────── the way out after a failed restore ─────────

func TestRestart_AfterARestoreThatFailedBeforeT2_TheProjectCanBeRestartedOrDeleted(t *testing.T) {
	for _, kind := range []string{"restart", "delete"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			failVerifyAt(e, 2, 3)
			r := e.runner()
			failed := e.restart(r, ref, withGUC("max_connections", "200"))
			stop := e.start(r)
			e.waitState(failed, "failed")
			stop()
			e.ag.setErr(nil)
			// A restore supersedes the failed restart and fails before T2:
			// the project is still restarting, with no failed restart left.
			ctx := context.Background()
			restore, sup, err := e.st.SubmitRestore(ctx, ref, json.RawMessage(`{}`))
			must(t, err)
			if sup != failed {
				t.Fatalf("superseded %d, want %d", sup, failed)
			}
			sql(t, "update operation set state = 'failed', last_error = 'internal: before T2' where id = $1", restore)
			if p := e.project(ref); p.State != "restarting" {
				t.Fatalf("project %+v", p)
			}
			e.start(r)
			if kind == "restart" {
				id := e.restart(r, ref, withGUC("max_connections", "300"))
				e.waitState(id, "done")
				if p := e.project(ref); p.State != "active" || p.Config.GUC["max_connections"] != "300" {
					t.Fatalf("project %+v", p)
				}
			} else {
				_, purge := e.deleted(r, ref)
				e.waitState(purge, "done")
				if p := e.project(ref); p.State != "purged" {
					t.Fatalf("project %+v", p)
				}
			}
			if op := e.op(restore); op.State != "failed" {
				t.Fatalf("restore %+v", op)
			}
		})
	}
}

// withIO is c with its device limits replaced.
func withIO(c store.ProjectConfig, limits *store.IOLimits) store.ProjectConfig {
	return store.ProjectConfig{DiskQuotaMB: c.DiskQuotaMB, MemMB: c.MemMB, GUC: c.GUC, Layout: c.Layout,
		UploadMBPerDay: c.UploadMBPerDay, UploadObjectsPerDay: c.UploadObjectsPerDay, Outbound: c.Outbound,
		Image: c.Image, ImageVersion: c.ImageVersion, IO: limits}
}

// A layout-2 project without a stanza (a switch that stopped before its
// first backup) has nothing to push: R2 records skipped and asks for none.
func TestRestart_DrainPushWithoutAStanzaIsSkipped(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout2)
	sql(t, "update backup_state set stanza_created = false where subject = $1", ref)
	r := e.runner()
	id := e.restart(r, ref, to2(layout2))
	e.start(r)
	op := e.waitState(id, "done")
	if n := len(e.ag.callsOf(ref, "Jobs.PushNow")); n != 0 || paramOf(op, "drain_push") != "skipped" {
		t.Fatalf("%d pushes, params %s", n, op.Params)
	}
}
