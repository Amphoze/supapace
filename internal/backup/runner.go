// Package backup runs the node's backup jobs: two lanes of two workers each
// over the persisted job queue, the scheduler that queues the regular pushes,
// replications and forced full backups, and the recording of what each job's
// end says.
//
// A job's result is written inside a container that handles a project's data,
// so everything in it is that project's to choose. The runner parses it
// strictly, bounds and checks every field before anything reaches the store,
// records a job whose result does not pass as crashed, and lets a result
// decide only that project's own state.
package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/Amphoze/supapace/internal/walname"
)

// Agent is every node-agent method the runner calls; *agent.Agent satisfies it.
type Agent interface {
	RunJob(context.Context, agent.JobSpec) (agent.JobResult, error)
	KillJobs(context.Context, string) error
	SetReplicatorQuota(context.Context, int) error
	EnsureRecovery(context.Context, agent.Spec, pgconf.RecoveryTarget) error
	RecoveryState(context.Context, agent.Spec) (promoted, exited bool, err error)
	QuotaUse(context.Context, int) (agent.QuotaUse, error)
	RepoSpace(context.Context) (sizeMB, freeMB int64, err error)
	RemoveFetch(context.Context, agent.Spec) error
	StopCluster(context.Context, string) error
	ContainmentFailed() bool
}

// Projects is what the runner asks the daemon about a project.
type Projects interface {
	SpecFor(ctx context.Context, ref string) (agent.Spec, error)
	Adopted(ref string) bool // not in the daemon's pending set
}

// Runner is the job runner. Its unexported timing fields are shortened by tests.
type Runner struct {
	st  *store.Store
	ts  tickStore // st, as the scheduler reads it (a test counts the calls)
	ag  Agent
	pr  Projects
	kek secrets.KEK
	cfg nodecfg.Config
	p   nodecfg.Paths
	log *slog.Logger

	now         func() time.Time
	idle        time.Duration         // a lane's pause after a turn that picked nothing
	tick        time.Duration         // the scheduler's
	recoverPoll time.Duration         // a recover job's poll of the recovery
	pushWait    func(context.Context) // PushNow's pause between two reads of its push job
	pickDelay   func() time.Duration  // before each backup-lane pick
	retry       time.Duration         // the first pause before a failed record is tried again
	stopPoll    time.Duration         // stop's re-read of the jobs it waits for

	mu         sync.Mutex
	decl       offsite.Declaration
	state      offsite.State
	addrs      []netip.AddrPort
	active     map[int64]*activeJob // running jobs of this process, by id
	lastHourly time.Time            // the scheduler's goroutine only
}

// activeJob is a running job: cancel stops it, code is why it was stopped
// (the code its end is recorded with), done is closed once it is recorded.
type activeJob struct {
	kind   string
	cancel context.CancelFunc
	code   string
	done   chan struct{}
}

func New(st *store.Store, ag Agent, pr Projects, kek secrets.KEK, c nodecfg.Config, p nodecfg.Paths) *Runner {
	return &Runner{st: st, ts: st, ag: ag, pr: pr, kek: kek, cfg: c, p: p, log: slog.Default(),
		now: time.Now, idle: time.Second, tick: bklimit.SchedulerTick, recoverPoll: 2 * time.Second, pushWait: func(ctx context.Context) { sleep(ctx, time.Second) },
		pickDelay: func() time.Duration { return rand.N(2*time.Second + 1) },
		retry:     time.Second, stopPoll: time.Second,
		state: offsite.StateUndeclared, active: map[int64]*activeJob{}}
}

// Start makes the queue match the node before anything is picked: every job
// container, every recovery cluster and every job file is removed, and only
// then is every running job ended interrupted — a subject's slot is never
// freed while a container of it may still write its repository. A failed
// removal fails Start and touches no job.
func (r *Runner) Start(ctx context.Context) error {
	if err := r.ag.KillJobs(ctx, ""); err != nil {
		return fmt.Errorf("backup: removing job containers: %w", err)
	}
	n, err := r.st.InterruptJobs(ctx)
	if n > 0 {
		r.log.Info("backup jobs interrupted by the restart", "jobs", n)
	}
	return err
}

// Run runs the two lanes of two workers each and the scheduler until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, lane := range []string{"push", "push", "backup", "backup"} {
		wg.Go(func() { r.lane(ctx, lane) })
	}
	wg.Go(func() { r.schedule(ctx) })
	wg.Wait()
}

// SetOffsite is called by the daemon's resolver loop once the address set is
// installed: addrs is the loaded set.
func (r *Runner) SetOffsite(d offsite.Declaration, st offsite.State, addrs []netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decl, r.state, r.addrs = d, st, slices.Clone(addrs)
}

// Offsite is the declaration's state: undeclared, partial or declared.
func (r *Runner) Offsite() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.state)
}

func (r *Runner) offsite() (offsite.Declaration, offsite.State, []netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.decl, r.state, slices.Clone(r.addrs)
}

// entry is the record of running job id, made by whichever of its lane and a
// canceller comes first.
func (r *Runner) entry(id int64) *activeJob {
	a := r.active[id]
	if a == nil {
		a = &activeJob{done: make(chan struct{})}
		r.active[id] = a
	}
	return a
}

// stop stops each running job with code and waits until each is recorded.
// While it waits it asks reread (which also cancels queued jobs that arrived
// since) which of them still run, every stopPoll: a job that ended without
// a lane of this process recording it is not waited on, and its entry goes.
func (r *Runner) stop(ctx context.Context, running []store.Job, reread func(context.Context) ([]store.Job, error), code string) error {
	for {
		var wait chan struct{}
		r.mu.Lock()
		for _, j := range running {
			a := r.entry(j.ID)
			a.code = code
			if a.cancel != nil {
				a.cancel()
			}
			if wait == nil {
				wait = a.done
			}
		}
		r.mu.Unlock()
		if wait == nil {
			return nil
		}
		select {
		case <-wait:
		case <-time.After(r.stopPoll):
		case <-ctx.Done():
			return ctx.Err()
		}
		still, err := reread(ctx)
		if err != nil {
			return err
		}
		r.mu.Lock()
		for _, j := range running {
			// Not running any more and never taken by a lane: nobody closes it.
			if a := r.active[j.ID]; a != nil && a.cancel == nil && !slices.ContainsFunc(still, func(s store.Job) bool { return s.ID == j.ID }) {
				delete(r.active, j.ID)
			}
		}
		r.mu.Unlock()
		running = still
	}
}

// stopKinds stops every running job of the kinds with code, without waiting.
func (r *Runner) stopKinds(code string, kinds ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.active {
		if a.cancel != nil && a.code == "" && slices.Contains(kinds, a.kind) {
			a.code = code
			a.cancel()
		}
	}
}

// Cancel ends operation opID's queued jobs and stops its running one, which
// is recorded cancelled before Cancel returns. The store changes no
// operation: call it only for an operation that has left waiting_job.
func (r *Runner) Cancel(ctx context.Context, opID int64) error {
	reread := func(ctx context.Context) ([]store.Job, error) { return r.st.CancelJobs(ctx, opID) }
	running, err := reread(ctx)
	if err != nil {
		return err
	}
	return r.stop(ctx, running, reread, "cancelled")
}

// CancelSubject does what Cancel does for every job of subject.
func (r *Runner) CancelSubject(ctx context.Context, subject string) error {
	reread := func(ctx context.Context) ([]store.Job, error) { return r.st.CancelSubjectJobs(ctx, subject) }
	running, err := reread(ctx)
	if err != nil {
		return err
	}
	return r.stop(ctx, running, reread, "cancelled")
}

// PushNow asks for a push of subject (none is queued while one is queued or
// running) and, while wait lasts, asks again as long as the last push ended
// incomplete. Outcomes: ok (a push ended complete), incomplete (the wait
// ended after an incomplete push), timeout (the wait ended while a push was
// queued or running; always so for a wait of 0), failed.
func (r *Runner) PushNow(ctx context.Context, subject string, wait time.Duration) (string, error) {
	end := r.now().Add(wait)
	id, err := r.askPush(ctx, subject)
	if err != nil {
		return "", err
	}
	if wait <= 0 {
		return "timeout", nil
	}
	for {
		if r.pushWait(ctx); ctx.Err() != nil {
			return "", ctx.Err()
		}
		now := r.now() // read before the job: a job seen unfinished was so at this time
		j, ok, err := r.st.LastJob(ctx, subject, "push")
		if err != nil {
			return "", err
		}
		if !ok || j.ID < id || busy(j) {
			if now.After(end) {
				return "timeout", nil
			}
			id = max(id, j.ID) // a newer push serves as well
			continue
		}
		if j.State == "failed" {
			return "failed", nil
		}
		v, _, err := jobio.ParseResult("push", j.Result)
		if res, isPush := v.(jobio.PushResult); err == nil && isPush && res.Complete {
			return "ok", nil
		}
		if !now.Before(end) {
			return "incomplete", nil
		}
		if id, err = r.askPush(ctx, subject); err != nil {
			return "", err
		}
	}
}

// askPush returns the subject's queued or running push, or queues one.
func (r *Runner) askPush(ctx context.Context, subject string) (int64, error) {
	j, ok, err := r.st.LastJob(ctx, subject, "push")
	if err != nil {
		return 0, err
	}
	if ok && (j.State == "queued" || j.State == "running") {
		return j.ID, nil
	}
	disk, repo, err := r.quotas(ctx, subject)
	if err != nil {
		return 0, err
	}
	return r.submit(ctx, subject, "push", disk, repo)
}

// quotas are the subject's disk and repository quotas in MiB.
func (r *Runner) quotas(ctx context.Context, subject string) (disk, repo int, err error) {
	if subject == nodecfg.ControlPlaneSubject {
		disk, repo = nodecfg.CPQuotas(r.cfg, r.p)
		return disk, repo, nil
	}
	p, err := r.st.GetProject(ctx, subject)
	if err != nil {
		return 0, 0, err
	}
	return p.Config.DiskQuotaMB, p.Config.DiskQuotaMB, nil // the repository quota equals the disk quota
}

// submit queues a job no operation owns, in its kind's lane, with its
// kind's deadline.
func (r *Runner) submit(ctx context.Context, subject, kind string, disk, repo int) (int64, error) {
	d, err := bklimit.Deadline(kind, disk, repo)
	if err != nil {
		return 0, err
	}
	return r.ts.SubmitJob(ctx, store.NewJob{Subject: subject, Lane: laneOf(kind), Kind: kind, DeadlineS: int(d / time.Second)})
}

// recoverJob starts the recovery cluster with the job's target and a serve
// job beside it, then polls the recovery until it has promoted, exited or
// run past the job's deadline. At promotion the serve job is stopped and its
// result kept; on every other outcome the serve job is stopped and the
// recovery cluster removed before the failure is recorded.
func (r *Runner) recoverJob(ctx context.Context, j store.Job, s subject) outcome {
	target, err := parseRecoverParams(j.Params)
	if err != nil {
		return failed("internal", err.Error())
	}
	deadline := r.now().Add(time.Duration(j.DeadlineS) * time.Second)
	sj := j
	sj.Kind = "serve"
	spec, err := r.jobSpec(ctx, sj, s)
	if err != nil {
		return specFailure(err)
	}
	sctx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	served := make(chan *jobio.ServeResult, 1)
	code, msg := "", ""
	if err := r.ag.EnsureRecovery(ctx, s.spec, target); err != nil {
		code, msg = "recovery_failed", "recovery start: "+err.Error()
		served <- nil
	} else {
		go func() { served <- serveResult(r.ag.RunJob(sctx, spec)) }()
		code, msg = r.awaitRecovery(ctx, s, deadline)
	}
	stopServe()
	sv := <-served
	if code == "" {
		res, err := jobio.MarshalResult(jobio.RecoverResult{OK: true, Promoted: true, Serve: sv})
		if err != nil {
			return failed("internal", err.Error())
		}
		return outcome{state: "done", result: res}
	}
	if err := r.ag.StopCluster(context.WithoutCancel(ctx), s.name); err != nil {
		r.log.Error("removing a recovery cluster", "subject", s.name, "job", j.ID, "err", clean(err.Error()))
	}
	if code == "recovery_failed" && sv != nil && sv.LastNone {
		code = "target_not_reached"
	}
	return failed(code, msg)
}

// awaitRecovery polls until promotion (code ""), exit, an error, the deadline
// or the end of ctx.
func (r *Runner) awaitRecovery(ctx context.Context, s subject, deadline time.Time) (code, msg string) {
	for {
		promoted, exited, err := r.ag.RecoveryState(ctx, s.spec)
		switch {
		case ctx.Err() != nil:
			return "interrupted", "the recover job was stopped"
		case err != nil:
			return "recovery_failed", "recovery state: " + err.Error()
		case promoted:
			return "", ""
		case exited:
			return "recovery_failed", "the recovery cluster exited before it promoted"
		case !r.now().Before(deadline):
			return "deadline", "the recovery did not promote within the job's deadline"
		}
		select {
		case <-ctx.Done():
		case <-time.After(r.recoverPoll):
		}
	}
}

// serveResult is a stopped serve job's result, nil when it left none that
// passes: exit 0, counts not negative, every name it answered a request name
// (last_segment a segment), so that what is stored stays small.
func serveResult(res agent.JobResult, err error) *jobio.ServeResult {
	if err != nil || res.ExitCode != 0 || len(res.Result) == 0 {
		return nil
	}
	v, _, err := jobio.ParseResult("serve", res.Result)
	sv, ok := v.(jobio.ServeResult)
	if err != nil || !ok || sv.Served < 0 || sv.Refused < 0 || !requestName(sv.Last) ||
		sv.LastSegment != "" && !segRE.MatchString(sv.LastSegment) {
		return nil
	}
	for _, n := range sv.None {
		if n == "" || !requestName(n) {
			return nil
		}
	}
	return &sv
}

// requestName: empty, or a name the archive binary may ask for.
func requestName(n string) bool {
	_, _, ok := walname.Request(n)
	return n == "" || ok
}

// errLog logs a lane's or the scheduler's store errors at most every 30 s.
type errLog struct {
	what string
	last time.Time
	n    int
}

func (e *errLog) report(log *slog.Logger, err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	e.n++
	if now := time.Now(); now.Sub(e.last) >= 30*time.Second {
		log.Error(e.what, "err", clean(err.Error()), "failures", e.n)
		e.last, e.n = now, 0
	}
}
