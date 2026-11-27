// Package saga is the node's operation worker: it carries project
// operations (create, restart, delete, purge) through their recorded steps
// against the control-plane store and the node agent, one operation at a
// time on the node.
//
// Every step first checks whether its effect already exists, so a worker
// that dies between a step's effect and recording the step only repeats a
// no-op when the operation resumes. Failures roll forward: a failed step is
// retried with back-off and, after the fifth attempt, the operation is
// failed at that step with nothing undone; only an explicit abort of a create
// (or a create that cannot be placed) runs the compensation list.
//
// The worker holds the project's ref lock for the whole of an attempt, so
// nothing else (an abort's compensation, the boot-time adoption loop) acts on
// the project beside a step. While the node's containment flag is set the
// worker takes no operation.
//
// Secrets never leave the store and the agent's spec in clear: no error, log
// line, last_error or operation parameter carries one, and text from a
// project's cluster or from Docker is sanitised and bounded before it is
// stored or logged.
package saga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/routes"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

// Agent is every node-agent method the steps call; *agent.Agent satisfies it.
type Agent interface {
	EnsureDir(context.Context, agent.Spec) error                      // create 3
	SetQuota(context.Context, agent.Spec) error                       // restart R3 (cluster stopped)
	DiskUsage(context.Context, agent.Spec) (int64, error)             // restart R1
	EnsureNetwork(context.Context, agent.Spec) error                  // create 3
	RemoveNetwork(context.Context, string) error                      // delete D4, abort C6
	EnsureCluster(context.Context, agent.Spec) error                  // create 4a, 4 (one phase per call; FirstBoot only there); restart R3, R4
	VerifyCluster(context.Context, agent.Spec) error                  // restart R4
	StopCluster(context.Context, string) error                        // restart R3, delete D3, purge P1, abort C3
	Prevalidate(context.Context, agent.Spec) error                    // restart R1
	PromoteCandidate(context.Context, string) error                   // restart R3
	EnsurePostgREST(context.Context, agent.Spec) error                // create 9, restart R5
	StopPostgREST(context.Context, string) error                      // restart R2, delete D2, purge P1, abort C2
	RouteFor(agent.Spec, string) routes.Project                       // create 11, restart R2, R5
	SetRoute(context.Context, string, *routes.Project) (int64, error) // create 11, restart R2, R5, delete D1, abort C1
	GatewayGeneration(context.Context) (int64, error)                 // create 11, restart R5, delete D1
	ProbeREST(context.Context, string, string) error                  // create 11, restart R5
	RemoveRender(context.Context, string) error                       // purge P3, abort C5
	PurgeDir(context.Context, agent.Spec) error                       // purge P4, abort C6
	ContainmentFailed() bool                                          // Run takes no operation while true

	EnsureRepoDir(context.Context, agent.Spec) error                // create 3, restart S1, restore T1
	EnsureSpoolDirs(context.Context, agent.Spec) error              // restart S1
	GrantBackupRole(context.Context, agent.Spec) error              // restart S2
	PurgeRepo(context.Context, agent.Spec) error                    // purge P4, abort C6
	RemoveFetch(context.Context, agent.Spec) error                  // restore T5a, T11
	RenderCluster(context.Context, agent.Spec) error                // restore T1 (replaced node)
	WipeData(context.Context, agent.Spec) error                     // restore T5
	HostState(context.Context, agent.Spec) (agent.HostState, error) // restore submit and T1

	SetReadOnlyLogin(context.Context, agent.Spec) error // restart R6
}

// Jobs is what the steps need from the backup job runner; *backup.Runner
// satisfies it.
type Jobs interface {
	Cancel(ctx context.Context, opID int64) error            // abort C0
	CancelSubject(ctx context.Context, subject string) error // delete D1, purge P1 and P4
	// PushNow asks for push jobs of subject until one is complete or wait is
	// over: ok, incomplete, timeout or failed; wait 0 asks and returns.
	PushNow(ctx context.Context, subject string, wait time.Duration) (outcome string, err error) // restart R2, create 12a
	Offsite() string                                                                             // "undeclared", "partial" or "declared"
}

// Recoverer re-keys a restored cluster and returns its timeline (restore T8).
type Recoverer interface {
	Rekey(context.Context, agent.Spec) (timeline int, err error)
}

const (
	maxAttempts         = 5    // attempts of a step before the operation is failed
	maxCompensationRuns = 8    // failed compensation runs before an abort is parked
	maxLastError        = 1024 // bytes of last_error
	kekID               = "node"
	clusterPids         = 512 // the cluster container's pids limit (the project's admission share adds PostgREST's 64)
)

// Runner is the worker. Its unexported timing fields are shortened by tests.
type Runner struct {
	st  *store.Store
	ag  Agent
	kek secrets.KEK
	cfg nodecfg.Config
	p   nodecfg.Paths
	log *slog.Logger

	worker sync.Mutex // held by Run: one worker per runner

	backoff          []time.Duration // after failed attempt n: backoff[min(n, len)-1]
	stepDeadline     time.Duration
	attemptDeadline  time.Duration
	containmentRetry time.Duration // requeue delay of an operation refused while the node is not contained
	probeWindow      time.Duration // how long create 11 and restart R5 retry the end-to-end probe
	probeEvery       time.Duration
	idle             time.Duration // between polls of an empty or paused queue
	waitEvery        time.Duration // how soon a step that waits without a job (create 12b) is taken again
	cpWait           time.Duration // how long create 12b waits for the control plane's segment off-site

	jobs Jobs      // nil: a step that needs a job fails with code internal
	rc   Recoverer // nil: restore T8 fails with code internal
}

func New(st *store.Store, ag Agent, kek secrets.KEK, c nodecfg.Config, p nodecfg.Paths) *Runner {
	return &Runner{st: st, ag: ag, kek: kek, cfg: c, p: p, log: slog.Default(),
		backoff:      []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second},
		stepDeadline: 300 * time.Second, attemptDeadline: 900 * time.Second, containmentRetry: 10 * time.Second,
		probeWindow: 60 * time.Second, probeEvery: time.Second, idle: time.Second,
		waitEvery: 5 * time.Second, cpWait: 900 * time.Second}
}

// SetJobs gives the runner its job runner; call it before Run.
func (r *Runner) SetJobs(j Jobs) { r.jobs = j }

// SetRecoverer gives the runner the restore's re-key; call it before Run.
func (r *Runner) SetRecoverer(rc Recoverer) { r.rc = rc }

func (r *Runner) backoffAfter(n int) time.Duration {
	return r.backoff[max(min(n, len(r.backoff)), 1)-1]
}

// step is one row of a step table. Its id is what operation.step records.
type step struct {
	id string
	do func(*job, context.Context) error
}

// errFinished is returned by a step whose own write recorded it and ended
// the operation (create step 12).
var errFinished = errors.New("operation finished by its step")

var tables = map[string][]step{
	"create":  createSteps,
	"restart": restartSteps,
	"delete":  deleteSteps,
	"purge":   purgeSteps,
	"restore": restoreSteps,
}

// job is one attempt at one operation.
type job struct {
	r      *Runner
	op     store.Operation
	held   func(context.Context) error // the ref lock is still held
	step   string                      // the step running
	layout int                         // a create's or a delete's project layout
}

// Run is the worker: it takes the next ready operation and runs one attempt
// of it, one operation at a time, until ctx ends. While the agent reports the
// node's containment as failed it takes nothing. A second Run on the same
// runner waits for the first to return.
func (r *Runner) Run(ctx context.Context) {
	r.worker.Lock()
	defer r.worker.Unlock()
	var queue queueErrors
	for ctx.Err() == nil {
		if !r.ag.ContainmentFailed() {
			op, ok, err := r.st.NextOperation(ctx)
			if ctx.Err() == nil {
				queue.report(r.log, time.Now(), err, r.text)
			}
			if ok {
				r.attempt(ctx, op)
				continue
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(r.idle):
		}
	}
}

// attempt runs one attempt of op under its ref lock.
func (r *Runner) attempt(ctx context.Context, op store.Operation) {
	unlock, held, err := r.st.LockRefChecked(ctx, op.Ref)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("ref lock", "ref", op.Ref, "op", op.ID, "err", r.text(err))
		}
		return
	}
	defer unlock()
	x := &job{r: r, held: held}
	// Re-read under the lock: an abort or a retry may have come in between.
	cur, err := r.st.GetOperation(ctx, op.ID)
	if err != nil {
		r.log.Error("operation", "ref", op.Ref, "op", op.ID, "err", r.text(err))
		return
	}
	x.op = cur
	switch {
	case cur.State == "aborting":
		x.compensate(ctx, "")
		return
	case cur.State != "pending" && cur.State != "running":
		return
	case cur.Kind == "create" && compensating(cur.Params):
		// Its compensation has run: it never goes forward again, whatever
		// put it back in the queue (an `op retry` of a parked abort).
		x.resumeCompensation(ctx)
		return
	}
	if err := r.st.StartOperation(ctx, cur.ID); err != nil {
		x.afterError(ctx, err)
		return
	}
	x.op.State, x.op.Attempts = "running", cur.Attempts+1
	// Attempts are counted when started, so a step that ends the process
	// every time cannot be resumed forever.
	// The fifth counted failure of a job is ended here, with its own code and
	// message, kept in last_error.
	if x.op.Attempts-requeues(x.op.Params) > maxAttempts {
		if cur.LastError != "" {
			x.finishFailedMsg(ctx, cur.LastError)
			return
		}
		x.finishFailed(ctx, final("internal", errors.New("interrupted too many times before finishing a step (the daemon stopped during each attempt); the operator can retry it")))
		return
	}
	actx, cancel := context.WithTimeout(ctx, r.attemptDeadline)
	defer cancel()
	if err := x.steps(ctx, actx); err != nil {
		x.afterError(ctx, err)
	}
}

// errLockLost ends an attempt whose ref lock went with its connection:
// nothing more is recorded, the queue takes the operation again.
var errLockLost = errors.New("ref lock lost")

// record checks, before a step's completion is written, that the ref lock is
// still held.
func (x *job) record(ctx context.Context) error {
	if err := x.held(ctx); err != nil {
		return fmt.Errorf("%w: %v", errLockLost, err)
	}
	return nil
}

func (x *job) finishFailed(ctx context.Context, err error) {
	x.finishFailedMsg(ctx, x.r.lastError(err))
}

func (x *job) finishFailedMsg(ctx context.Context, msg string) {
	if x.record(ctx) != nil {
		return
	}
	msg = x.restoreNote(ctx, x.stranded(ctx, msg))
	if err := x.r.st.FinishOperation(ctx, x.op.ID, "failed", msg); err != nil {
		x.r.log.Error("recording a failed operation", "op", x.op.ID, "ref", x.op.Ref, "err", x.r.text(err))
		return
	}
	x.r.log.Warn("step failed", "op", x.op.ID, "ref", x.op.Ref, "kind", x.op.Kind, "after", x.op.Step,
		"attempt", x.op.Attempts, "final", true, "err", msg)
	x.finished("failed")
}

// steps runs the operation's table from the step after the recorded one,
// then finishes it done. Store bookkeeping uses ctx; steps run under actx
// (the attempt deadline) and each under its own step deadline.
func (x *job) steps(ctx, actx context.Context) error {
	table := tables[x.op.Kind]
	if table == nil {
		return final("internal", fmt.Errorf("unknown operation kind %q", x.op.Kind))
	}
	i, err := x.start(ctx, table)
	if err != nil {
		return err
	}
	if x.op.Kind == "create" || x.op.Kind == "delete" {
		p, err := x.r.st.GetProject(ctx, x.op.Ref)
		if err != nil {
			return err
		}
		x.layout = p.Config.Layout
	}
	for ; i < len(table); i++ {
		s := table[i]
		if x.op.Kind == "create" && createLayout2[s.id] && x.layout != 2 ||
			x.op.Kind == "delete" && deleteLayout2[s.id] && x.layout != 2 ||
			x.op.Kind == "restart" && restartLayout2[s.id] && !x.toLayout2() {
			continue
		}
		hitFailpoint(x.r.p, x.op.Kind+":"+s.id)
		x.step = s.id
		sctx, cancel := context.WithTimeout(actx, x.r.stepDeadline)
		err := s.do(x, sctx)
		cancel()
		var pk *parked
		if errors.As(err, &pk) {
			return x.park(ctx, pk.job)
		}
		var lt *later
		if errors.As(err, &lt) {
			return x.requeue(ctx, lt)
		}
		var rw *rewind
		if errors.As(err, &rw) {
			if err := x.rewind(ctx, table, rw); err != nil {
				return err
			}
			if actx.Err() != nil {
				return actx.Err()
			}
			i = indexOf(table, rw.to) - 1
			continue
		}
		var rf *rollForward
		if errors.As(err, &rf) {
			// Restart R3 or R4 failed: write the rollback target first, so a resumed
			// operation continues the rollback, then re-enter R1.
			if err := x.rollForward(ctx, rf); err != nil {
				return err
			}
			if actx.Err() != nil {
				return actx.Err()
			}
			i = indexOf(table, "R1") - 1
			continue
		}
		if errors.Is(err, errFinished) {
			x.op.Step = s.id
			x.r.log.Info("step done", "op", x.op.ID, "ref", x.op.Ref, "kind", x.op.Kind, "step", s.id)
			x.finished("done")
			return nil
		}
		if err != nil {
			return err
		}
		if err := x.record(ctx); err != nil {
			return err
		}
		if err := x.r.st.AdvanceStep(ctx, x.op.ID, s.id); err != nil {
			return err
		}
		x.op.Step = s.id
		x.r.log.Info("step done", "op", x.op.ID, "ref", x.op.Ref, "kind", x.op.Kind, "step", s.id)
	}
	if err := x.record(ctx); err != nil {
		return err
	}
	state, note := x.outcome()
	if err := x.r.st.FinishOperation(ctx, x.op.ID, state, note); err != nil {
		return err
	}
	if note != "" {
		state = "rolled_back"
	}
	x.finished(state)
	return nil
}

// finished logs the one summary line of an operation that has ended: no
// error text (the failure's own line carries it), no parameters.
func (x *job) finished(outcome string) {
	level := slog.LevelInfo
	if outcome != "done" {
		level = slog.LevelWarn
	}
	x.r.log.Log(context.Background(), level, "operation finished", "op", x.op.ID, "ref", x.op.Ref, "kind", x.op.Kind,
		"outcome", outcome, "step", x.op.Step, "attempts", x.op.Attempts,
		"duration", time.Since(x.op.CreatedAt).Round(time.Millisecond).String())
}

// start returns the index of the first step to run: the one after the
// recorded step (create's step 1 is the admin API's, outside the table).
func (x *job) start(ctx context.Context, table []step) (int, error) {
	if x.op.Kind == "restart" {
		return x.restartStart(ctx, table)
	}
	return indexOf(table, x.op.Step) + 1, nil
}

func indexOf(table []step, id string) int {
	for i, s := range table {
		if s.id == id {
			return i
		}
	}
	return -1
}

// failure is an error the step tables mark with its last_error code and
// whether it is retried.
type failure struct {
	code  string
	final bool // not retried: the operation is failed at once
	err   error
}

func (f *failure) Error() string { return f.code + ": " + f.err.Error() }
func (f *failure) Unwrap() error { return f.err }

func final(code string, err error) error { return &failure{code: code, final: true, err: err} }

// code maps an error to its last_error code.
func code(err error) string {
	var f *failure
	switch {
	case errors.As(err, &f):
		return f.code
	case errors.Is(err, store.ErrNodeFull):
		return "node_full"
	case errors.Is(err, agent.ErrContainment) && !errors.Is(err, agent.ErrCheckIncomplete):
		return "containment_failed"
	case errors.Is(err, agent.ErrStaleGeneration):
		return "stale_generation"
	case errors.Is(err, agent.ErrEpochDivergence):
		return "epoch_divergence"
	case errors.Is(err, bootstrap.ErrAssertion):
		return "assertion"
	case errors.Is(err, pgsock.ErrPeer):
		return "peer"
	case pgsock.IsBudget(err):
		return "timeout"
	}
	return "internal"
}

// text sanitises and bounds an error's text for a log line or last_error.
func (r *Runner) text(err error) string {
	var f *failure
	if errors.As(err, &f) {
		err = f.err
	}
	return pgsock.Sanitize(err.Error(), maxLastError)
}

// lastError is "<code>: <message>", sanitised, at most 1 KiB.
func (r *Runner) lastError(err error) string {
	return pgsock.Sanitize(code(err)+": "+r.text(err), maxLastError)
}

// afterError applies the failure policy to an attempt of op that ended with
// err. It re-reads the operation first: an abort requested while the step
// ran makes the step's own writes fail with ErrConflict, and the worker that
// holds the lock compensates now.
func (x *job) afterError(ctx context.Context, err error) {
	r, op := x.r, x.op
	if ctx.Err() != nil {
		return // the worker is stopping; the operation resumes at its recorded step
	}
	if errors.Is(err, errLockLost) || x.record(ctx) != nil {
		r.log.Warn("ref lock lost; attempt ended, nothing recorded", "op", op.ID, "ref", op.Ref, "kind", op.Kind)
		return
	}
	cur, gerr := r.st.GetOperation(ctx, op.ID)
	if gerr != nil {
		r.log.Error("operation", "ref", op.Ref, "op", op.ID, "err", r.text(gerr))
		return
	}
	x.op = cur
	if cur.State == "aborting" {
		x.compensate(ctx, "")
		return
	}
	if cur.State != "running" {
		return
	}
	msg := r.lastError(err)
	// logRetry logs a failure that is not the operation's end; a final one
	// is logged as final once it is recorded.
	logRetry := func(in time.Duration) {
		r.log.Warn("step failed", "op", op.ID, "ref", op.Ref, "kind", op.Kind, "after", cur.Step,
			"attempt", cur.Attempts, "final", false, "retry_in", in.String(), "err", msg)
	}
	var f *failure
	var werr error
	requeued := requeues(cur.Params)
	switch {
	case errors.Is(err, store.ErrNodeFull) && op.Kind == "create":
		// Nothing to resume: straight to the compensation list.
		r.log.Warn("step failed", "op", op.ID, "ref", op.Ref, "kind", op.Kind, "after", cur.Step,
			"attempt", cur.Attempts, "final", true, "compensating", true, "err", msg)
		if _, werr = r.st.RequestAbort(ctx, op.Ref); werr == nil {
			cur, werr = r.st.GetOperation(ctx, op.ID)
		}
		if werr == nil {
			x.op = cur
			x.compensate(ctx, msg)
			return
		}
	case errors.Is(err, agent.ErrContainment) && r.ag.ContainmentFailed():
		// The node's fault, not the project's: back in the queue, not
		// counted against the attempts, taken again once the flag clears.
		logRetry(r.containmentRetry)
		if werr = r.patchParams(ctx, &cur, "requeued", requeued+1); werr == nil {
			werr = r.st.FailAttempt(ctx, op.ID, msg, time.Now().Add(r.containmentRetry))
		}
	case errors.Is(err, agent.ErrContainment) && !errors.Is(err, agent.ErrCheckIncomplete), errors.Is(err, bootstrap.ErrAssertion), errors.Is(err, agent.ErrEpochDivergence),
		errors.As(err, &f) && f.final, cur.Attempts-requeued >= maxAttempts:
		msg = x.restoreNote(ctx, x.stranded(ctx, msg))
		if werr = r.st.FinishOperation(ctx, op.ID, "failed", msg); werr == nil {
			r.log.Warn("step failed", "op", op.ID, "ref", op.Ref, "kind", op.Kind, "after", cur.Step,
				"attempt", cur.Attempts, "final", true, "err", msg)
			x.finished("failed")
		}
	default:
		in := r.backoffAfter(cur.Attempts - requeued)
		logRetry(in)
		werr = r.st.FailAttempt(ctx, op.ID, msg, time.Now().Add(in))
	}
	if werr != nil {
		if errors.Is(werr, store.ErrConflict) {
			// An abort landed between the re-read and the write.
			if cur, gerr := r.st.GetOperation(ctx, op.ID); gerr == nil && cur.State == "aborting" {
				x.op = cur
				x.compensate(ctx, "")
				return
			}
		}
		r.log.Error("recording a failed attempt", "op", op.ID, "ref", op.Ref, "err", r.text(werr))
	}
}

// requeues is the number of attempts given back for a containment refusal.
func requeues(params json.RawMessage) int {
	var p struct {
		Requeued int `json:"requeued"`
	}
	json.Unmarshal(params, &p)
	return p.Requeued
}

// patchParams sets one member of the operation's parameters.
func (r *Runner) patchParams(ctx context.Context, op *store.Operation, key string, v any) error {
	m := map[string]json.RawMessage{}
	if len(op.Params) > 0 {
		if err := json.Unmarshal(op.Params, &m); err != nil {
			return err
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m[key] = b
	params, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := r.st.SetOperationParams(ctx, op.ID, params); err != nil {
		return err
	}
	op.Params = params
	return nil
}

// Submit queues a restart or delete of an active project; creates are
// inserted by the admin API and picked up by Run. A restart's params are
// {"base_generation": N, "config": <complete target configuration>}; the
// operation stores {"base_generation", "prev": <configuration of N>,
// "next": <target>} and is refused with store.ErrConflict when the project is
// no longer at generation N. A delete takes no params.
func (r *Runner) Submit(ctx context.Context, kind, ref string, params json.RawMessage) (int64, error) {
	if kind == "restore" {
		return r.submitRestore(ctx, ref, params)
	}
	if kind != "restart" && kind != "delete" {
		return 0, fmt.Errorf("%w: operation kind %q cannot be submitted", store.ErrConflict, kind)
	}
	p, err := r.st.GetProject(ctx, ref)
	if err != nil {
		return 0, err
	}
	if kind == "delete" {
		return r.st.SubmitOperation(ctx, ref, kind, nil, p.Generation, time.Now())
	}
	var in struct {
		BaseGeneration int64               `json:"base_generation"`
		Config         store.ProjectConfig `json:"config"`
	}
	if err := strictJSON(params, &in); err != nil {
		return 0, fmt.Errorf("restart parameters: %w", err)
	}
	// prev is read outside the admitting transaction; the generation check
	// there proves it is still the configuration of base_generation.
	out, err := json.Marshal(restartParams{BaseGeneration: in.BaseGeneration, Prev: p.Config, Next: in.Config})
	if err != nil {
		return 0, err
	}
	return r.st.SubmitOperation(ctx, ref, kind, out, in.BaseGeneration, time.Now())
}

// Abort marks the ref's create aborting and returns its id; the worker that
// holds or next takes the ref lock compensates.
func (r *Runner) Abort(ctx context.Context, ref string) (int64, error) {
	return r.st.RequestAbort(ctx, ref)
}

// queueErrorEvery: while the queue cannot be read (the store is down), its
// error is logged at most this often.
const queueErrorEvery = 30 * time.Second

// queueErrors keeps the worker's log readable while the store is down: the
// first failure, then at most one line every queueErrorEvery while it
// persists, and one line when the queue can be read again.
type queueErrors struct {
	failing     bool
	since, last time.Time
	n           int // failures since the last line
}

func (q *queueErrors) report(log *slog.Logger, now time.Time, err error, text func(error) string) {
	switch {
	case err != nil && !q.failing:
		q.failing, q.since, q.last, q.n = true, now, now, 0
		log.Error("operation queue", "err", text(err))
	case err != nil:
		q.n++
		if now.Sub(q.last) >= queueErrorEvery {
			log.Error("operation queue", "err", text(err), "failures", q.n, "since", q.since.UTC().Format(time.RFC3339))
			q.last, q.n = now, 0
		}
	case q.failing:
		q.failing = false
		log.Info("operation queue readable again", "down_for", now.Sub(q.since).Round(time.Second).String())
	}
}
