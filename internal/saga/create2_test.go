package saga

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// declared makes the fake runner's off-site store declared and replicates
// the control plane's segment as soon as a create asks for its push (12a).
func (e *env) declared() {
	e.jobs.offsite.Store("declared")
	must(e.t, e.st.EnsureBackupState(context.Background(), "cp"))
	e.jobs.onPush = func(subject string) {
		ops, err := e.st.ListOperations(context.Background(), "")
		if err != nil {
			e.t.Error(err)
			return
		}
		for _, op := range ops {
			if seg := paramOf(op, "cp_segment"); seg != "" && op.State == "running" {
				e.markCP(seg)
			}
		}
	}
}

// markCP records segment seg of the control plane as replicated.
func (e *env) markCP(seg string) {
	bs, err := e.st.GetBackupState(context.Background(), "cp")
	if err != nil {
		e.t.Error(err)
		return
	}
	key := "archive/cp-" + bs.Incarnation + "/17-1/" + seg[:16] + "/" + seg + "-" + strings.Repeat("a", 40) + ".zst"
	sql(e.t, "insert into offsite_object (subject, key, size, uploaded_at, launch) values ('cp', $1, 1, now() - interval '1 second', 0) on conflict do nothing", key)
	sql(e.t, "update backup_state set last_repl_ok = now() where subject = 'cp'")
}

// A layout-1 create is the create as built: the same steps and agent calls,
// in order, no job, no call of the job runner, no passphrase, no position.
func TestCreate_Layout1_AsBuilt(t *testing.T) {
	e := newEnv(t)
	e.declared()
	e.jobs.onPush = nil
	e.lanes(nil)
	ref, id := e.create()
	e.start(e.runner())
	op := e.waitState(id, "done")
	e.summaries(id, 1) // the last step's line is written after the state
	wantSeq(t, e.steps(id), createIDs)
	wantSeq(t, e.ag.methods(ref), []string{"EnsureDir", "EnsureNetwork", "EnsureCluster", "EnsureCluster",
		"EnsurePostgREST", "SetRoute", "ProbeREST"})
	if slices.ContainsFunc(e.ag.methods(""), func(m string) bool { return strings.HasPrefix(m, "Jobs.") }) {
		t.Fatalf("job runner called: %v", e.ag.methods(""))
	}
	if len(e.jobsOf(id)) != 0 || e.jobs.pushes.Load() != 0 || op.Attempts != 1 {
		t.Fatalf("jobs %v, pushes %d, op %+v", e.jobsOf(id), e.jobs.pushes.Load(), op)
	}
	if paramOf(op, "cp_lsn") != "" || paramOf(op, "job_floor") != "" {
		t.Fatalf("params %s", op.Params)
	}
	if _, _, err := e.st.GetSecret(context.Background(), ref, "backup.cipher_pass"); err == nil {
		t.Fatal("a layout-1 create made a stanza passphrase")
	}
	if _, err := e.st.GetBackupState(context.Background(), ref); err == nil {
		t.Fatal("a layout-1 create made a backup state row")
	}
}

func TestCreate_Step3EnsuresRepoDirAndBackupState(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref, id := e.create2(layout2)
	e.start(e.runner())
	e.waitState(id, "done")
	wantSeq(t, e.ag.methods(ref)[:3], []string{"EnsureDir", "EnsureRepoDir", "EnsureNetwork"})
	e.ag.locked(func() {
		for _, s := range e.ag.specs {
			if s.Layout != 2 || s.RepoQuotaMB != 8192 {
				t.Fatalf("spec layout %d repository quota %d", s.Layout, s.RepoQuotaMB)
			}
		}
	})
	bs, err := e.st.GetBackupState(context.Background(), ref)
	must(t, err)
	if bs.Incarnation != "1" {
		t.Fatalf("backup state %+v", bs)
	}
}

func TestCreate_Steps5aTo5d_Order(t *testing.T) {
	e := newEnv(t)
	e.declared()
	e.lanes(nil)
	_, id := e.create2(layout2)
	e.start(e.runner())
	e.waitState(id, "done")
	e.summaries(id, 1) // the last step's line is written after the state
	wantSeq(t, e.steps(id), createIDs2)
	wantSeq(t, e.jobSteps(id), []string{"5a/stanza-create", "5b/backup", "5c/check", "5d/replicate"})
}

// 5a completes at once when the stanza exists.
func TestCreate_5aSkipsAnExistingStanza(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref, id := e.create2(layout2)
	e.failpoint("create:5a")
	<-e.run(e.runner())
	must(t, e.st.MarkStanza(context.Background(), ref))
	e.start(e.runner())
	e.waitState(id, "done")
	wantSeq(t, e.jobSteps(id), []string{"5b/backup", "5c/check"})
}

func TestCreate_ReplicateLoopsWhileCapsOrRebuild(t *testing.T) {
	e := newEnv(t)
	e.declared()
	results := []string{
		`{"ok":true,"mode":"copy","complete":false,"stopped":"caps","uploaded":4,"adopted":0}`,
		`{"ok":true,"mode":"rebuild","complete":false,"stopped":"rebuild"}`,
		// The rebuild's last page: the record is whole, nothing is copied yet.
		`{"ok":true,"mode":"rebuild","complete":true,"stopped":""}`,
		`{"ok":true,"mode":"copy","complete":true,"stopped":"","uploaded":1,"adopted":0}`,
	}
	var n atomic.Int32
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind != "replicate" {
			return okEnd
		}
		return jobEnd{state: "done", result: results[n.Add(1)-1]}
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	e.waitState(id, "done")
	wantSeq(t, e.jobSteps(id)[3:], []string{"5d/replicate", "5d/replicate", "5d/replicate", "5d/replicate"})
}

// A replication that stops for its budget, an upload failure or a segment
// held back fails the step: the operation fails at 5c.
func TestCreate_ReplicateStopFailsTheStep(t *testing.T) {
	for _, stop := range []string{"budget", "upload-failed", "held"} {
		t.Run(stop, func(t *testing.T) {
			e := newEnv(t)
			e.declared()
			e.lanes(func(j store.Job) jobEnd {
				if j.Kind != "replicate" {
					return okEnd
				}
				return jobEnd{state: "done", result: `{"ok":true,"mode":"copy","complete":false,"stopped":"` + stop + `","uploaded":1,"adopted":0}`}
			})
			_, id := e.create2(layout2)
			e.start(e.runner())
			op := e.waitState(id, "failed")
			if op.Step != "5c" || !strings.HasPrefix(op.LastError, "replication_stopped: ") || !strings.Contains(op.LastError, stop) {
				t.Fatalf("op %+v", op)
			}
			if n := len(e.jobsOf(id)); n != 4 {
				t.Fatalf("%d jobs", n)
			}
		})
	}
}

func TestCreate_Undeclared_5dAnd12bAreEnteredAndCompleteAtOnce(t *testing.T) {
	for _, state := range []string{"undeclared", "partial"} {
		t.Run(state, func(t *testing.T) {
			e := newEnv(t)
			e.jobs.offsite.Store(state)
			e.lanes(nil)
			_, id := e.create2(layout2)
			for _, s := range []string{"5d", "12b"} {
				e.failpoint("create:" + s)
				<-e.run(e.runner()) // the failpoint fires: the step is entered
				if op := e.op(id); op.State != "running" {
					t.Fatalf("at %s: %+v", s, op)
				}
			}
			e.start(e.runner())
			e.waitState(id, "done")
			wantSeq(t, e.jobSteps(id), []string{"5a/stanza-create", "5b/backup", "5c/check"})
			if n := len(e.logs.records("waiting without a job")); n != 0 {
				t.Fatalf("%d waits", n)
			}
			if slices.Contains(e.steps(id), "12b") != true {
				t.Fatal("12b not recorded")
			}
		})
	}
}

func TestCreate_Step2RecordsPosition(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	_, id := e.create2(layout2)
	e.failpoint("create:3")
	<-e.run(e.runner())
	lsn := paramOf(e.op(id), "cp_lsn")
	if !regexp.MustCompile(`^[0-9A-F]+/[0-9A-F]+$`).MatchString(lsn) {
		t.Fatalf("cp_lsn %q", lsn)
	}
	// A resumed step 2 keeps the position it recorded.
	sql(t, "update operation set step = '1' where id = $1", id)
	sql(t, "select pg_switch_wal()")
	e.start(e.runner())
	op := e.waitState(id, "done")
	if got := paramOf(op, "cp_lsn"); got != lsn {
		t.Fatalf("cp_lsn %q, was %q", got, lsn)
	}
	if !regexp.MustCompile(`^[0-9A-F]{24}$`).MatchString(paramOf(op, "cp_segment")) {
		t.Fatalf("cp_segment %q", paramOf(op, "cp_segment"))
	}
	if c := e.ag.callsOf("cp", "Jobs.PushNow"); len(c) != 1 {
		t.Fatalf("pushes of cp %+v", c)
	}
}

// 12b waits without a job: each round gives its attempt back and leaves
// last_error as it is; one log line for the whole wait.
func TestCreate_12bRequeuesQuietly(t *testing.T) {
	e := newEnv(t)
	e.declared()
	e.jobs.onPush = nil
	e.lanes(nil)
	_, id := e.create2(layout2)
	sql(t, "update operation set last_error = 'earlier: kept' where id = $1", id)
	e.start(e.runner())
	seen := map[time.Time]bool{}
	deadline := time.Now().Add(30 * time.Second)
	for len(seen) < 5 {
		op := e.op(id)
		if op.Step == "12a" && op.State == "pending" {
			if op.Attempts != 0 || op.LastError != "earlier: kept" {
				t.Fatalf("waiting op %+v", op)
			}
			seen[op.UpdatedAt] = true
		}
		if time.Now().After(deadline) {
			t.Fatalf("saw %d rounds; op %+v", len(seen), op)
		}
		time.Sleep(time.Millisecond)
	}
	e.replicateCP(id)
	op := e.waitState(id, "done")
	if op.Attempts != 1 {
		t.Fatalf("op %+v", op)
	}
	if n := len(e.logs.records("waiting without a job")); n != 1 {
		t.Fatalf("%d wait lines", n)
	}
}

func TestCreate_12bThen900sFails(t *testing.T) {
	e := newEnv(t)
	if New(e.st, e.ag, e.kek, e.cfg, e.p).cpWait != 900*time.Second {
		t.Fatal("the wait is not 900 s")
	}
	e.declared()
	e.jobs.onPush = nil
	e.lanes(nil)
	_, id := e.create2(layout2)
	r := e.runner()
	r.cpWait = 300 * time.Millisecond
	e.start(r)
	op := e.waitState(id, "failed")
	if op.Step != "12a" || !strings.HasPrefix(op.LastError, "cp_not_replicated: ") {
		t.Fatalf("op %+v", op)
	}
	if paramOf(op, "wait_started") == "" {
		t.Fatalf("params %s", op.Params)
	}
	// Control: replicated, a retry finishes it.
	seg := paramOf(op, "cp_segment")
	e.markCP(seg)
	must(t, e.st.RetryOperation(context.Background(), id))
	e.waitState(id, "done")
}

func TestCreate_StanzaPassphraseSecretOnce(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref, id := e.create2(layout2)
	e.failpoint("create:3")
	<-e.run(e.runner())
	pass := e.secret(ref, "backup.cipher_pass")
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(pass) {
		t.Fatalf("passphrase of %d characters", len(pass))
	}
	sql(t, "update operation set step = '1' where id = $1", id)
	e.start(e.runner())
	e.waitState(id, "done")
	if e.secret(ref, "backup.cipher_pass") != pass {
		t.Fatal("the passphrase was made again")
	}
}

func TestCreate_Layout2Spec(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref, id := e.create2(layout2)
	e.start(e.runner())
	e.waitState(id, "done")
	s, err := e.runner().SpecFor(context.Background(), ref)
	must(t, err)
	if s.Layout != 2 || s.RepoQuotaMB != 8192 || s.Stanza != ref+"-1" || s.StanzaPass != e.secret(ref, "backup.cipher_pass") {
		t.Fatalf("spec layout %d quota %d stanza %q, passphrase set %v", s.Layout, s.RepoQuotaMB, s.Stanza, s.StanzaPass != "")
	}
	// Layout 1: the repository quota is filled, no stanza.
	ref1 := e.active()
	s, err = e.runner().SpecFor(context.Background(), ref1)
	must(t, err)
	if s.Layout != 0 || s.RepoQuotaMB != 8192 || s.Stanza != "" || s.StanzaPass != "" {
		t.Fatalf("layout-1 spec layout %d quota %d stanza %q", s.Layout, s.RepoQuotaMB, s.Stanza)
	}
}

func TestCreate_OpRetrySubmitsFreshJobs(t *testing.T) {
	e := newEnv(t)
	var fail atomic.Bool
	fail.Store(true)
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "check" && fail.Load() {
			return jobEnd{state: "failed", code: "pgbackrest", msg: "check failed"}
		}
		return okEnd
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if op.Step != "5b" {
		t.Fatalf("op %+v", op)
	}
	old := e.jobsOf(id)
	fail.Store(false)
	must(t, e.st.RetryOperation(context.Background(), id))
	e.waitState(id, "done")
	all := e.jobsOf(id)
	fresh := all[len(old):]
	if len(fresh) != 1 || fresh[0].OpStep != "5c" || fresh[0].State != "done" || fresh[0].ID <= old[len(old)-1].ID {
		t.Fatalf("after the retry %+v", fresh)
	}
	for _, j := range old[2:] {
		if j.OpStep != "5c" || j.State != "failed" {
			t.Fatalf("old job %+v", j)
		}
	}
}

func TestCreate_FailedJobIsSubmittedAgain(t *testing.T) {
	e := newEnv(t)
	var n atomic.Int32
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "backup" && n.Add(1) == 1 {
			return jobEnd{state: "failed", code: "archive_timeout", msg: "late"}
		}
		return okEnd
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	op := e.waitState(id, "done")
	wantSeq(t, e.jobSteps(id), []string{"5a/stanza-create", "5b/backup", "5b/backup", "5c/check"})
	if op.Attempts != 2 {
		t.Fatalf("op %+v", op)
	}
}

// Failpoints create:5a … create:12b: a worker stopped before each step
// resumes it; each job is submitted once and every node object made once.
func TestCreate_ResumeFromEachLayout2Step(t *testing.T) {
	for _, s := range []string{"5a", "5b", "5c", "5d", "12a", "12b"} {
		t.Run(s, func(t *testing.T) {
			e := newEnv(t)
			e.declared()
			e.lanes(nil)
			ref, id := e.create2(layout2)
			e.failpoint("create:" + s)
			<-e.run(e.runner())
			if op := e.op(id); op.State != "running" {
				t.Fatalf("after the failpoint: %+v", op)
			}
			e.start(e.runner())
			e.waitState(id, "done")
			if p := e.project(ref); p.State != "active" {
				t.Fatalf("project %s", p.State)
			}
			wantSeq(t, e.jobSteps(id), []string{"5a/stanza-create", "5b/backup", "5c/check", "5d/replicate"})
			e.ag.locked(func() {
				for k, n := range e.ag.effects {
					if n != 1 {
						t.Errorf("effect %q happened %d times", k, n)
					}
				}
			})
		})
	}
}
