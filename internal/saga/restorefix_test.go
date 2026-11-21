package saga

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/store"
)

// The restore's fixture: a layout-2 project created to done, three recorded
// sets on timeline 1, a complete push, and lanes that end every job as the
// test says (by default: done, with results shaped as the runner stores
// them). Every job's pick is recorded in the fake agent's call list as
// "job:<step>:<kind>", so its order against the agent's calls is visible.

// rAgent is the fake agent with a quota report the test sets.
type rAgent struct {
	*fakeAgent
	quotaFull atomic.Bool
}

func (a *rAgent) HostState(ctx context.Context, s agent.Spec) (agent.HostState, error) {
	h, err := a.fakeAgent.HostState(ctx, s)
	h.QuotaFull = a.quotaFull.Load()
	return h, err
}

const (
	seg2 = "000000010000000000000002"
	seg4 = "000000010000000000000004"
	seg6 = "000000010000000000000006"
	seg8 = "000000010000000000000008"
	seg9 = "000000010000000000000009"
	segA = "00000001000000000000000A"
)

type rx struct {
	e   *env
	ag  *rAgent
	r   *Runner
	ref string

	base   time.Time // set A stops here, B an hour later, C two hours later
	bjob   int64     // the create's backup job: the sets' job
	sets   []string  // labels A, B, C
	create int64

	stopWorker, stopLanes func()

	mu     sync.Mutex
	n      map[string]int // jobs picked, by "<step>:<kind>"
	newest map[string]string
	hist   []string // nil: the recorded timelines'
	reach  string   // the serve's last segment
	fetchH []string
	onJob  func(j store.Job, n int) (jobEnd, bool)
	rekey  func(ctx context.Context, s agent.Spec, pending int) (int, error)
}

func newRx(t *testing.T) *rx { return newRxWith(t, layout2) }

func newRxWith(t *testing.T, cfg store.ProjectConfig) *rx {
	t.Helper()
	if prev := openRx[t]; prev != nil {
		prev.close() // a second fixture in one test: the first one's goroutines end before its schema goes
	}
	e := newEnv(t)
	x := &rx{e: e, ag: &rAgent{fakeAgent: e.ag}, n: map[string]int{},
		newest: map[string]string{"00000001": seg9}, reach: seg9, fetchH: []string{}}
	openRx[t] = x
	t.Cleanup(func() { delete(openRx, t) })
	x.lanes()
	x.r = e.runner()
	x.r.ag = x.ag
	x.r.SetRecoverer(x)
	ref, id := e.create2(cfg)
	stop := e.start(x.r)
	e.waitState(id, "done")
	stop()
	x.ref, x.create = ref, id
	for _, j := range e.jobsOf(id) {
		if j.Kind == "backup" {
			x.bjob = j.ID
		}
	}
	ctx := context.Background()
	x.base = time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)
	for i, s := range []struct{ start, stop, lsn string }{{seg2, "000000010000000000000003", "0/3000100"},
		{seg4, "000000010000000000000005", "0/5000100"}, {seg6, "000000010000000000000007", "0/7000100"}} {
		at := x.base.Add(time.Duration(i) * time.Hour)
		label := at.Format("20060102-150405") + "F"
		must(t, e.st.RecordSet(ctx, store.BackupSet{Subject: ref, Label: label, TLI: 1, StartSegment: s.start, StopSegment: s.stop,
			StartLSN: "0/" + strings.TrimLeft(s.start[16:], "0") + "000028", StopLSN: s.lsn, StartAt: at.Add(-10 * time.Minute), StopAt: at, JobID: x.bjob}))
		x.sets = append(x.sets, label)
	}
	must(t, e.st.RecordPush(ctx, ref, store.PushRecord{Complete: true, NewestSegment: seg9, At: time.Now()}))
	e.ag.reset()
	return x
}

// Rekey is the fake re-key: it is recorded as an agent call (so the fake's
// error and hook apply) and answers the operation's pending timeline.
func (x *rx) Rekey(ctx context.Context, s agent.Spec) (int, error) {
	if err := x.ag.enter(ctx, call{Method: "Rekey", Ref: s.Ref}, nil); err != nil {
		return 0, err
	}
	pending := 0
	tls, err := x.e.st.Timelines(ctx, s.Ref)
	if err != nil {
		return 0, err
	}
	for _, t := range tls {
		if t.State == "pending" {
			pending = t.TLI
		}
	}
	x.mu.Lock()
	f := x.rekey
	x.mu.Unlock()
	if f != nil {
		return f(ctx, s, pending)
	}
	return pending, nil
}

func (x *rx) set(fn func()) {
	x.mu.Lock()
	defer x.mu.Unlock()
	fn()
}

// end ends job j: by onJob when it answers, else by its kind's default.
func (x *rx) end(j store.Job) jobEnd {
	x.ag.enter(context.Background(), call{Method: "job:" + j.OpStep + ":" + j.Kind, Ref: j.Subject}, nil)
	x.mu.Lock()
	k := j.OpStep + ":" + j.Kind
	x.n[k]++
	n, f := x.n[k], x.onJob
	newest, hist, reach, fetchH := x.newest, x.hist, x.reach, x.fetchH
	// The test's callback runs under the lock: what it writes, the test reads with x.set.
	if f != nil {
		if out, ok := f(j, n); ok {
			x.mu.Unlock()
			return out
		}
	}
	x.mu.Unlock()
	switch j.Kind {
	case "push":
		if hist == nil { // an honest repository: the history of every recorded timeline above 1
			hist = []string{}
			for _, t := range x.timelines() {
				if t.TLI > 1 && t.State == "recorded" {
					hist = append(hist, fmt.Sprintf("%08X.history", t.TLI))
				}
			}
		}
		return jobEnd{state: "done", result: pushRes(true, newest, hist)}
	case "replicate":
		return replDone
	case "fetch":
		return jobEnd{state: "done", result: fetchRes(fetchH)}
	case "restore":
		var p struct{ Mode string }
		json.Unmarshal(j.Params, &p)
		return jobEnd{state: "done", result: `{"ok":true,"mode":"` + p.Mode + `"}`}
	case "recover":
		return jobEnd{state: "done", result: recoverRes(reach)}
	}
	return okEnd
}

func pushRes(complete bool, newest map[string]string, hist []string) string {
	b, _ := json.Marshal(map[string]any{"ok": true, "complete": complete, "pushed": 0, "first": "", "last": "", "newest": newest,
		"quarantined": []any{}, "remaining": 0, "other_entries": 0, "spool_entries": 0, "spool_bytes": 0, "spool_oldest": nil,
		"histories": hist})
	return string(b)
}

func fetchRes(hist []string) string {
	m := map[string]any{"ok": true, "files": 3, "bytes": 300}
	if len(hist) > 0 { // the runner leaves the member out when empty
		m["histories"] = hist
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func recoverRes(last string) string {
	return `{"ok":true,"promoted":true,"serve":{"ok":true,"served":3,"none":[],"refused":0,"last":"","last_none":false,"last_segment":"` + last + `"}}`
}

func failEnd(code string) jobEnd {
	return jobEnd{state: "failed", code: code, msg: code + " in the test"}
}

// on ends the jobs of one step and kind by fn (n: how many of them have been
// picked so far, this one included); the others by default.
func (x *rx) on(step, kind string, fn func(n int) jobEnd) {
	x.set(func() {
		prev := x.onJob
		x.onJob = func(j store.Job, n int) (jobEnd, bool) {
			if j.OpStep == step && j.Kind == kind {
				return fn(n), true
			}
			if prev != nil {
				return prev(j, n)
			}
			return jobEnd{}, false
		}
	})
}

// submit queues a restore of the fixture's project.
func (x *rx) submit(to string, timeline int, from string) (int64, error) {
	b, _ := json.Marshal(map[string]any{"to": to, "timeline": timeline, "from": from})
	return x.r.Submit(context.Background(), "restore", x.ref, b)
}

func (x *rx) mustSubmit(to string, timeline int, from string) int64 {
	x.e.t.Helper()
	id, err := x.submit(to, timeline, from)
	must(x.e.t, err)
	return id
}

// run submits and runs a restore to its end (done or failed).
func (x *rx) run(to string, timeline int, from string) store.Operation {
	x.e.t.Helper()
	id := x.mustSubmit(to, timeline, from)
	return x.finish(id)
}

func (x *rx) finish(id int64) store.Operation {
	x.e.t.Helper()
	if x.stopWorker == nil { // one worker a runner: a second Run would wait for the first
		x.stopWorker = x.e.start(x.r)
	}
	x.e.wait(id, "ended", func(op store.Operation) bool { return op.State == "done" || op.State == "failed" })
	// T11 ends the operation inside its step: the worker's last lines come
	// after the row. Its summary line is the end.
	for deadline := time.Now().Add(30 * time.Second); !x.ended(id); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			x.e.t.Fatalf("operation %d: no summary line", id)
		}
	}
	return x.e.op(id)
}

// ended: the worker logged operation id's summary line.
func (x *rx) ended(id int64) bool {
	for _, m := range x.e.logs.records("operation finished") {
		if m["op"] == float64(id) {
			return true
		}
	}
	return false
}

// declare makes the off-site store declared and every set replicated and
// listed.
func (x *rx) declare() {
	x.e.jobs.offsite.Store("declared")
	sql(x.e.t, "update backup_set set replicated = true, listed_at = stop_at + interval '1 minute' where subject = $1", x.ref)
}

// replaced makes the node hold nothing of the project.
func (x *rx) replaced() {
	x.ag.locked(func() {
		delete(x.ag.dir, x.ref)
		delete(x.ag.state, x.ref)
		delete(x.ag.cluster, x.ref)
		delete(x.ag.network, x.ref)
		delete(x.ag.pgrest, x.ref)
	})
}

// timeline inserts a timeline row (a recorded one above 1 carries a launch number).
func (x *rx) timeline(tli int, state string, op int64) {
	var opv any
	if op != 0 {
		opv = op
	}
	sql(x.e.t, "insert into backup_timeline (subject, tli, state, op_id, launch) values ($1, $2, $3, $4, $5)", x.ref, tli, state, opv, tli)
}

// recordKey adds an uploaded object to the record of the fixture's project.
func (x *rx) recordKey(rel string) {
	sql(x.e.t, "insert into offsite_object (subject, key, size, uploaded_at, launch) values ($1, $2, 1, now() - interval '1 minute', 1)",
		x.ref, "archive/"+x.ref+"-1/17-1/"+rel)
}

type jrow struct {
	ID     int64
	Step   string
	Kind   string
	State  string
	Code   string
	Params map[string]any
}

// jobs returns operation id's jobs of step ("" every step), oldest first,
// with their parameters.
func (x *rx) jobs(id int64, step string) []jrow {
	x.e.t.Helper()
	ctx := context.Background()
	cfg, err := pgx.ParseConfig("")
	must(x.e.t, err)
	cfg.Host, cfg.Port, cfg.Database, cfg.User = sockDir, 5432, "supapaced", "supapaced"
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	c, err := pgx.ConnectConfig(ctx, cfg)
	must(x.e.t, err)
	defer c.Close(ctx)
	rows, err := c.Query(ctx, `select id, op_step, kind, state, coalesce(code, ''), coalesce(params, '{}') from backup_job
		where op_id = $1 and ($2 = '' or op_step = $2) order by id`, id, step)
	must(x.e.t, err)
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (jrow, error) {
		var j jrow
		var p []byte
		err := r.Scan(&j.ID, &j.Step, &j.Kind, &j.State, &j.Code, &p)
		json.Unmarshal(p, &j.Params)
		return j, err
	})
	must(x.e.t, err)
	return out
}

func (x *rx) kinds(id int64) []string {
	var out []string
	for _, j := range x.jobs(id, "") {
		out = append(out, j.Step+"/"+j.Kind)
	}
	return out
}

// params is the operation's parameter document.
func (x *rx) params(id int64) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	json.Unmarshal(x.e.op(id).Params, &m)
	return m
}

func (x *rx) result(id int64) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	json.Unmarshal(x.e.op(id).Result, &m)
	return m
}

func (x *rx) timelines() map[int]store.Timeline {
	x.e.t.Helper()
	tls, err := x.e.st.Timelines(context.Background(), x.ref)
	must(x.e.t, err)
	m := map[int]store.Timeline{}
	for _, t := range tls {
		m[t.TLI] = t
	}
	return m
}

func (x *rx) notice(code string) (store.Notice, bool) {
	x.e.t.Helper()
	ns, err := x.e.st.ListNotices(context.Background(), x.ref)
	must(x.e.t, err)
	for _, n := range ns {
		if n.Code == code {
			return n, true
		}
	}
	return store.Notice{}, false
}

// calls is the order of the agent's calls and job picks for the project.
func (x *rx) calls() []string { return x.ag.methods(x.ref) }

// countOf is how many entries of seq equal s.
func countOf(seq []string, s string) int {
	n := 0
	for _, v := range seq {
		if v == s {
			n++
		}
	}
	return n
}

// before reports whether a occurs in seq and every b after it.
func before(seq []string, a, b string) bool {
	i := slices.Index(seq, a)
	return i >= 0 && !slices.Contains(seq[:i], b)
}

func raw(m map[string]json.RawMessage, k string) string { return string(m[k]) }

func wantCode(t *testing.T, op store.Operation, state, code string) {
	t.Helper()
	if op.State != state || !strings.HasPrefix(op.LastError, code+":") {
		t.Fatalf("operation %s %q, want %s with code %s", op.State, op.LastError, state, code)
	}
}

var _ = fmt.Sprint

// slot is the project's slot_op as text ("" when free).
func (x *rx) slot() string {
	x.e.t.Helper()
	ctx := context.Background()
	cfg, err := pgx.ParseConfig("")
	must(x.e.t, err)
	cfg.Host, cfg.Port, cfg.Database, cfg.User = sockDir, 5432, "supapaced", "supapaced"
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	c, err := pgx.ConnectConfig(ctx, cfg)
	must(x.e.t, err)
	defer c.Close(ctx)
	var s string
	must(x.e.t, c.QueryRow(ctx, "select coalesce(slot_op::text, '') from project where ref = $1", x.ref).Scan(&s))
	return s
}

// openRx is each running test's latest fixture.
var openRx = map[*testing.T]*rx{}

// lanes runs the queue's jobs as env.lanes does, ended by x.end, until
// close or the end of the test.
func (x *rx) lanes() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			picked := false
			for _, lane := range []string{"push", "backup"} {
				j, ok, err := x.e.st.NextJob(ctx, lane)
				if err != nil || !ok {
					continue
				}
				picked = true
				out := x.end(j)
				var res json.RawMessage
				if out.result != "" {
					res = json.RawMessage(out.result)
				}
				if out.state == "done" && j.Kind == "stanza-create" {
					x.e.st.MarkStanza(ctx, j.Subject)
				}
				if err := x.e.st.FinishJob(ctx, j.ID, out.state, out.code, out.msg, res); err != nil && ctx.Err() == nil {
					x.e.t.Errorf("finishing job %d: %v", j.ID, err)
				}
			}
			if !picked {
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Millisecond):
				}
			}
		}
	}()
	var once sync.Once
	x.stopLanes = func() { once.Do(func() { cancel(); <-done }) }
	x.e.t.Cleanup(x.stopLanes)
}

func (x *rx) close() {
	if x.stopWorker != nil {
		x.stopWorker()
	}
	x.stopLanes()
}

// sameJSON: a and b are the same JSON value (the store reorders members).
func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return a == b
	}
	return fmt.Sprint(x) == fmt.Sprint(y)
}

// recordedBy records timeline tli as made by a finished restore of set i.
func (x *rx) recordedBy(tli, i int) {
	sql(x.e.t, `insert into operation (ref, kind, state, params, epoch, generation)
		values ($1, 'restore', 'done', jsonb_build_object('set', $2::text), 1, 1)`, x.ref, x.sets[i])
	sql(x.e.t, `insert into backup_timeline (subject, tli, state, op_id, launch)
		values ($1, $2::int, 'recorded', (select max(id) from operation where ref = $1), $2::int)`, x.ref, tli)
}
