package saga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/Amphoze/supapace/internal/walname"
)

// A restore replaces a project's data in place with a backup set and the
// archive after it, to a time, a position or the end of the archive, from
// the project's repository or from the off-site store. Everything the steps
// read back — a job's result, the restored tree, the recovering server's
// answers — is the tenant's or derived from it: each figure is checked for
// its shape and bounds before it is stored, and none carries a platform
// guarantee on its own (the timeline the re-key reads must equal the one the
// platform chose; the shortfall is measured by the platform's serve job).
//
// The project's data directory is first changed at T5 (the wipe). Until T11
// the project is restoring and its route draining: it is never served from
// a cluster that is half restored or not yet re-keyed.
var restoreSteps = []step{
	{id: "T1", do: timed((*job).restoreHost)},
	{id: "T2", do: timed((*job).restoreDrain)},
	{id: "T3", do: timed((*job).restoreStop)},
	{id: "T4p", do: timed((*job).restorePush)},
	{id: "T4r", do: timed((*job).restoreHeld)},
	{id: "T5a", do: timed((*job).restoreFetch)},
	{id: "T5b", do: timed((*job).restoreSeed)},
	{id: "T5", do: timed((*job).restoreWipe)},
	{id: "T6", do: timed((*job).restoreFiles)},
	{id: "T7", do: timed((*job).restoreRecover)},
	{id: "T8", do: timed((*job).restoreRekey)},
	{id: "T9", do: timed((*job).restoreStart)},
	{id: "T10p", do: timed((*job).pushEmpty)},
	{id: "T10r", do: timed((*job).replicate)},
	{id: "T10c", do: timed(func(x *job, ctx context.Context) error {
		return x.awaitFinal(ctx, "check", restoredLink, "tablespace", "symlink")
	})},
	{id: "T10b", do: timed(func(x *job, ctx context.Context) error {
		return x.awaitFinal(ctx, "backup", restoredLink, "tablespace", "symlink")
	})},
	{id: "T10s", do: timed((*job).replicate)},
	{id: "T11", do: (*job).restoreFinish},
}

// restoredLink is why a check or backup of the restored cluster cannot pass.
const restoredLink = "the restored cluster cannot be checked or backed up as it is (a tablespace, a link, or a tree that " +
	"cannot be walked whole, from before the target): restore to a target before it"

// restoreOrder is restoreSteps for the steps themselves to read (a direct
// reference would make the table's initialisation a cycle).
var restoreOrder []step

func init() { restoreOrder = restoreSteps }

// restoreParams is the restore's parameter document as the steps read it.
// It is written member by member (patch), never whole: members other code
// writes (job_floor, requeued, repl_free) are kept.
type restoreParams struct {
	To           string            `json:"to"`
	Timeline     int               `json:"timeline"` // 0: the newest recorded
	From         string            `json:"from"`     // local, offsite
	Set          string            `json:"set"`
	SetStart     string            `json:"set_start_segment"`
	Replaced     bool              `json:"replaced"`
	N            int               `json:"n"` // the newest recorded timeline at T4r
	NNewest      string            `json:"n_newest_segment"`
	Reached      string            `json:"reached_segment"`
	Histories    []string          `json:"histories"` // the history files repo/ holds
	T7Started    bool              `json:"t7_started"`
	T8Done       bool              `json:"t8_done"`
	StandbyTried bool              `json:"standby_tried"`
	FetchExtra   int               `json:"fetch_extra"`
	Seeded       bool              `json:"seeded"`
	Newest       map[string]string `json:"newest"` // the last T4p push's; null: the record's (replaced node, first pass)
	Shortfall    json.RawMessage   `json:"shortfall"`
	Mode         string            `json:"mode"`
	Times        map[string]int    `json:"times"`
	Clock        *stepClock        `json:"clock"`
	Decided      *decision         `json:"decided"`
	Wiped        bool              `json:"wiped"`    // T5 has begun: the data directory is no longer the one before
	Switched     string            `json:"switched"` // why the source became the off-site store, the first time
}

// stepClock is when the step that waits (parked or later) was entered.
type stepClock struct {
	Step  string    `json:"step"`
	Start time.Time `json:"at"`
}

// decision is the rewind a failed job led to, written before the rewind:
// a step re-entered before the rewind's own writes repeats it, and does not
// decide again (a second widening, or a standby retry taken for a refusal).
type decision struct {
	Job    int64  `json:"job"`
	Target string `json:"to"`
}

func (x *job) rp() (restoreParams, error) {
	var p restoreParams
	if err := json.Unmarshal(x.op.Params, &p); err != nil {
		return p, final("internal", errors.New("the restore's parameters do not parse"))
	}
	return p, nil
}

// patch sets members of the operation's parameters in one write.
func (x *job) patch(ctx context.Context, kv map[string]any) error {
	m := map[string]json.RawMessage{}
	if len(x.op.Params) > 0 {
		if err := json.Unmarshal(x.op.Params, &m); err != nil {
			return err
		}
	}
	for k, v := range kv {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		m[k] = b
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := x.r.st.SetOperationParams(ctx, x.op.ID, b); err != nil {
		return err
	}
	x.op.Params = b
	return nil
}

// timed adds the seconds a step took — over its attempts, its parked waits
// included — to the parameters' times, which become the result's steps.
func timed(do func(*job, context.Context) error) func(*job, context.Context) error {
	return func(x *job, ctx context.Context) error {
		p, err := x.rp()
		if err != nil {
			return err
		}
		start := time.Now()
		if p.Clock != nil && p.Clock.Step == x.step {
			start = p.Clock.Start
		}
		err = do(x, ctx)
		// The bookkeeping has its own bound: the step's may be spent.
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		var pk *parked
		var lt *later
		var rw *rewind
		switch {
		case errors.As(err, &pk), errors.As(err, &lt):
			if p.Clock == nil || p.Clock.Step != x.step {
				if perr := x.patch(wctx, map[string]any{"clock": stepClock{x.step, start}}); perr != nil {
					return perr
				}
			}
		case err == nil, errors.As(err, &rw):
			q, perr := x.rp()
			if perr != nil {
				return perr
			}
			if q.Times == nil {
				q.Times = map[string]int{}
			}
			q.Times[x.step] += int(time.Since(start).Round(time.Second) / time.Second)
			if perr := x.patch(wctx, map[string]any{"times": q.Times, "clock": nil}); perr != nil {
				return perr
			}
		}
		return err
	}
}

// T1: the target rendered as the recovery start will take it — a refusal
// ends the restore here, final, with nothing changed; and on a node that
// holds nothing of the project (no project directory, no state file), the
// project materialised without a first boot, its source the off-site store.
func (x *job) restoreHost(ctx context.Context) error {
	p, err := x.rp()
	if err != nil {
		return err
	}
	if _, err := x.restoreTarget(ctx, p); err != nil {
		return err
	}
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	if !p.Replaced {
		hs, err := x.r.ag.HostState(ctx, s)
		// The state file, not the directory: a failed restore's T1 made that.
		if err != nil || hs.StateFile {
			return err
		}
		// Recorded first: once EnsureDir has run the node no longer looks
		// replaced.
		if err := x.patch(ctx, map[string]any{"replaced": true, "from": "offsite"}); err != nil {
			return err
		}
	}
	for _, f := range []func(context.Context, agent.Spec) error{x.r.ag.EnsureDir, x.r.ag.EnsureRepoDir, x.r.ag.EnsureNetwork, x.r.ag.RenderCluster} {
		if err := f(ctx, s); err != nil {
			return err
		}
	}
	return x.r.st.EnsureBackupState(ctx, x.op.Ref)
}

// restoreTarget renders the stored target; a refusal is final
// (invalid_target): no retry renders it otherwise.
func (x *job) restoreTarget(ctx context.Context, p restoreParams) (pgconf.RecoveryTarget, error) {
	tls, err := x.r.st.Timelines(ctx, x.op.Ref)
	if err != nil {
		return pgconf.RecoveryTarget{}, err
	}
	t, err := renderTarget(p.To, p.Timeline, tls)
	if errors.Is(err, pgconf.ErrGUCValue) || errors.Is(err, store.ErrConflict) {
		return t, final("invalid_target", err)
	}
	return t, err
}

// T2: the project restoring, its route draining with the gateway at that
// route file, PostgREST stopped.
func (x *job) restoreDrain(ctx context.Context) error {
	if err := x.r.st.SetProjectRestoring(ctx, x.op.Ref, x.op.ID); errors.Is(err, store.ErrConflict) {
		return final("conflict", err)
	} else if err != nil {
		return err
	}
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	rt := x.r.ag.RouteFor(s, "draining")
	gen, err := x.r.ag.SetRoute(ctx, x.op.Ref, &rt)
	if err != nil {
		return err
	}
	if err := x.r.waitGateway(ctx, gen); err != nil {
		return err
	}
	return x.r.ag.StopPostgREST(ctx, x.op.Ref)
}

// firstReplacedPass: on a replaced node before any recovery started there
// is nothing to stop, push or wipe.
func firstReplacedPass(p restoreParams) bool { return p.Replaced && !p.T7Started }

// T3: the cluster stopped and removed, whatever its start kind (a recovery
// start an earlier pass left included).
func (x *job) restoreStop(ctx context.Context) error {
	p, err := x.rp()
	if err != nil || firstReplacedPass(p) {
		return err
	}
	return x.r.ag.StopCluster(ctx, x.op.Ref)
}

// T4p: the project's slot taken by this restore (until T11), then push jobs
// until one reports the spool empty.
func (x *job) restorePush(ctx context.Context) error {
	if err := x.r.st.SetSlot(ctx, x.op.Ref, x.op.ID); err != nil {
		return err
	}
	p, err := x.rp()
	if err != nil || firstReplacedPass(p) {
		return err
	}
	return x.pushEmpty(ctx)
}

// pushEmpty is a push step: push jobs while the last says complete false, at
// most bklimit.PushLoopMax of this pass; past it the step fails, final (the
// same jobs would be counted again).
func (x *job) pushEmpty(ctx context.Context) error {
	j, ok, err := x.latestJob(ctx)
	if err != nil {
		return err
	}
	if ok && j.State == "done" {
		pr, err := pushOf(j)
		if err != nil {
			return err
		}
		if pr.Complete {
			return nil
		}
	}
	n, err := x.r.st.CountJobs(ctx, x.op.ID, x.step, jobFloor(x.op.Params))
	if err != nil {
		return err
	}
	proj, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return err
	}
	if max := bklimit.PushLoopMax(proj.Config.DiskQuotaMB); n >= max {
		return final("push_incomplete", fmt.Errorf("the spool was not pushed empty in %d push jobs; 'supapace op retry %d' pushes on from where it stopped", max, x.op.ID))
	}
	return x.submit(ctx, "push")
}

var (
	tliKeyRE  = regexp.MustCompile(`^[0-9A-F]{8}$`)
	segmentRE = regexp.MustCompile(`^[0-9A-F]{24}$`)
)

// pushResult is what the restore reads of a stored push result.
type pushResult struct {
	Complete  bool              `json:"complete"`
	Newest    map[string]string `json:"newest"`
	Histories []string          `json:"histories"`
}

// pushOf reads a done push job's stored result: newest at most 64
// timelines, each key 8 hex digits and its value a segment of that timeline;
// at most 64 history names. A history of a timeline the platform does not
// admit is kept: it is what the comparison at T4r looks for.
func pushOf(j store.Job) (pushResult, error) {
	var r pushResult
	err := json.Unmarshal(j.Result, &r)
	if err == nil && (len(r.Newest) > 64 || len(r.Histories) > 64) {
		err = errors.New("too many timelines")
	}
	for k, seg := range r.Newest {
		if kind, t, ok := walname.Spool(seg); err == nil && (!tliKeyRE.MatchString(k) || !ok || kind != walname.Segment || fmt.Sprintf("%08X", t) != k) {
			err = fmt.Errorf("newest %.16q: %.32q", k, seg)
		}
	}
	for _, h := range r.Histories {
		if kind, _, ok := walname.Spool(h); err == nil && (!ok || kind != walname.History) {
			err = fmt.Errorf("history %.32q", h)
		}
	}
	if err != nil {
		return r, final("internal", fmt.Errorf("push job %d: its stored result is out of shape: %v", j.ID, err))
	}
	return r, nil
}

// T4r: replication (in a new epoch the record's rebuild), then what repo/
// holds — n, its newest segment, the newest map and the held histories —
// from the last T4p push, or from the record when T4p did not push; and the
// comparison with the timelines: a held history of a timeline without a row
// (extra), or a recorded or abandoned timeline above 1 not held (missing),
// sends the restore to the off-site store.
func (x *job) restoreHeld(ctx context.Context) error {
	if err := x.replicate(ctx); err != nil {
		return err
	}
	p, err := x.rp()
	if err != nil {
		return err
	}
	tls, err := x.r.st.Timelines(ctx, x.op.Ref)
	if err != nil {
		return err
	}
	n := newestRecorded(tls)
	kv := map[string]any{"n": n}
	if firstReplacedPass(p) {
		bs, err := x.r.st.GetBackupState(ctx, x.op.Ref)
		if err != nil {
			return err
		}
		stanza := x.op.Ref + "-" + bs.Incarnation
		seg, err := x.r.st.NewestRecordedSegment(ctx, x.op.Ref, n)
		if err != nil {
			return err
		}
		// ponytail: one lookup a timeline row; rows planted by a listing make
		// this step slower, bounded by the listing's caps (a denial of that
		// project's restore only). Replaced at T5b by the fetch plan's list.
		held := []string{}
		for _, t := range tls {
			if t.TLI < 2 {
				continue
			}
			name := fmt.Sprintf("%08X.history", t.TLI)
			if ok, err := x.r.st.HasArchiveObject(ctx, x.op.Ref, stanza, name); err != nil {
				return err
			} else if ok {
				held = append(held, name)
			}
		}
		kv["n_newest_segment"], kv["newest"], kv["histories"] = seg, nil, held
		return x.patch(ctx, kv)
	}
	j, ok, err := x.r.st.LatestJob(ctx, x.op.ID, "T4p", jobFloor(x.op.Params))
	if err != nil {
		return err
	}
	if !ok || j.State != "done" {
		// op retry raised the floor above it: push again (one short job).
		return &rewind{to: "T4p", cause: errors.New("no done push of this pass")}
	}
	pr, err := pushOf(j)
	if err != nil {
		return err
	}
	hist, newest := pr.Histories, pr.Newest
	if hist == nil {
		hist = []string{}
	}
	if newest == nil { // null is the record's, at T7: a push that named none has none
		newest = map[string]string{}
	}
	kv["n_newest_segment"], kv["newest"], kv["histories"] = newest[fmt.Sprintf("%08X", n)], newest, hist
	if p.From == "local" {
		if why := compareHeld(tls, hist); why != "" {
			kv["from"] = "offsite"
			x.switched(p, kv, "the repository's history files differ from the platform's timelines")
			x.r.log.Info("restore goes off-site", "op", x.op.ID, "ref", x.op.Ref, "why", why)
		}
	}
	return x.patch(ctx, kv)
}

// compareHeld is "" when repo/'s history files agree with the timeline rows,
// else why not.
func compareHeld(tls []store.Timeline, hist []string) string {
	held := map[int]bool{}
	for _, t := range heldTimelines(hist) {
		held[t] = true
	}
	rows := map[int]string{}
	for _, t := range tls {
		rows[t.TLI] = t.State
	}
	for t := range held {
		if _, ok := rows[t]; !ok {
			return fmt.Sprintf("the repository holds the history of timeline %d, which has no row", t)
		}
	}
	for t, st := range rows {
		if t > 1 && (st == "recorded" || st == "abandoned") && !held[t] {
			return fmt.Sprintf("the repository lacks the history of %s timeline %d", st, t)
		}
	}
	return ""
}

// heldTimelines are the timelines of history names (already checked for
// their shape), above 1.
func heldTimelines(hist []string) []int {
	var out []int
	for _, h := range hist {
		if _, t, ok := walname.Spool(h); ok && t > 1 && t <= 1<<31-1 {
			out = append(out, int(t))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// T5a, off-site only: fetch/ emptied, then the fetch job; the runner builds
// its plan from the record.
func (x *job) restoreFetch(ctx context.Context) error {
	p, err := x.rp()
	if err != nil || p.From != "offsite" {
		return err
	}
	jobs, err := x.jobRunner()
	if err != nil {
		return err
	}
	if jobs.Offsite() != "declared" {
		return final("offsite_not_declared", fmt.Errorf("the off-site store is not declared: the restore needs its projects' read credential; "+
			"declare it with 'supapaced offsite set', then 'supapace op retry %d'", x.op.ID))
	}
	j, ok, err := x.latestJob(ctx)
	if err != nil || ok && j.State == "done" {
		return err
	}
	if ok && j.Code == "fetch_too_large" {
		return final("fetch_too_large", errors.New(j.Message))
	}
	// The seed that follows empties the repository: only after a copy of this
	// pass ended complete (the store may not have been declared at T4r).
	if cj, ok, err := x.r.st.LatestJob(ctx, x.op.ID, "T4r", jobFloor(x.op.Params)); err != nil {
		return err
	} else if !ok || !completeCopy(cj) {
		return &rewind{to: "T4p", cause: errors.New("no complete copy of this pass to the off-site store")} // T4r reads its push
	}
	sets, err := x.r.st.ListSets(ctx, x.op.Ref)
	if err != nil {
		return err
	}
	if i := slices.IndexFunc(sets, func(s store.BackupSet) bool { return s.Label == p.Set }); i < 0 || !sets[i].Replicated || sets[i].ListedAt == nil {
		return final("set_not_offsite", fmt.Errorf("backup set %s is not completely off-site; wait for replication ('supapace project backups %s') "+
			"and run 'supapace op retry %d', or restore to a target before that set", p.Set, x.op.Ref, x.op.ID))
	}
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	if err := x.r.ag.RemoveFetch(ctx, s); err != nil {
		return err
	}
	return x.submitParams(ctx, "fetch", map[string]any{"set": p.Set, "to": p.To, "timeline": p.Timeline, "extra": p.FetchExtra})
}

// submitParams parks on a fresh job of kind with params.
func (x *job) submitParams(ctx context.Context, kind string, params any) error {
	b, err := json.Marshal(params)
	if err != nil {
		return err
	}
	err = x.submit(ctx, kind)
	var pk *parked
	if errors.As(err, &pk) {
		pk.job.Params = b
	}
	return err
}

// T5b, off-site only: the seed job (repo/ replaced by fetch/); then the held
// histories are the fetch plan's, as the runner stored them with the fetch's
// result — never a list the fetch job reported. A seed that finds no fetch/
// (the launcher's source check, code host_state) goes back to T5a.
func (x *job) restoreSeed(ctx context.Context) error {
	p, err := x.rp()
	if err != nil || p.From != "offsite" {
		return err
	}
	j, ok, err := x.latestJob(ctx)
	if err != nil {
		return err
	}
	switch {
	case ok && j.State == "done":
		fj, ok, err := x.r.st.LatestJob(ctx, x.op.ID, "T5a", jobFloor(x.op.Params))
		if err != nil {
			return err
		}
		if !ok || fj.State != "done" {
			return &rewind{to: "T5a", cause: errors.New("no done fetch of this pass")}
		}
		var fr struct {
			Histories []string `json:"histories"` // absent when empty
		}
		err = json.Unmarshal(fj.Result, &fr)
		for _, h := range fr.Histories {
			if k, _, ok := walname.Spool(h); err == nil && (!ok || k != walname.History) {
				err = fmt.Errorf("history %.32q", h)
			}
		}
		if err == nil && len(fr.Histories) > 1<<16 {
			err = errors.New("too many histories")
		}
		if err != nil {
			return final("internal", fmt.Errorf("fetch job %d: its stored result is out of shape: %v", fj.ID, err))
		}
		if fr.Histories == nil {
			fr.Histories = []string{}
		}
		return x.patch(ctx, map[string]any{"seeded": true, "histories": fr.Histories})
	case ok && j.Code == "host_state":
		cause, counted := jobCause(j)
		return &rewind{to: "T5a", cause: cause, counted: counted}
	}
	// Recorded before the repository is emptied: a seed that fails part-way
	// leaves it seeded, so every older set is restored from off-site (the
	// runner writes the time again when the seed ends done).
	if err := x.r.st.SetSeeded(ctx, x.op.Ref, time.Now()); err != nil {
		return err
	}
	return x.submit(ctx, "seed")
}

// T5: the data directory wiped — the first step that changes it.
func (x *job) restoreWipe(ctx context.Context) error {
	p, err := x.rp()
	if err != nil || firstReplacedPass(p) {
		return err
	}
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	if err := x.patch(ctx, map[string]any{"wiped": true}); err != nil {
		return err
	}
	return x.r.ag.WipeData(ctx, s)
}

// T6: the restore job, in mode none; after a refusal 58 (history_mismatch),
// once in mode standby when the set lies on the timeline followed (named, or
// the newest recorded) — a 58 also comes from the history of a branch no
// restore finished; else the off-site store (a new source is a new pass: it
// may try standby once again). A set that records a tablespace or a link is
// final: no retry changes its manifest. Any other failed or interrupted job:
// back to T5 (wipe, then a fresh job).
func (x *job) restoreFiles(ctx context.Context) error {
	p, err := x.rp()
	if err != nil {
		return err
	}
	if p.From == "offsite" && !p.Seeded {
		// Off-site without a seed of this pass (a stop between a rewind's two
		// writes): fetch and seed first.
		return &rewind{to: "T5a", cause: errors.New("the off-site source has not been seeded in this pass")}
	}
	follow, err := x.followed(ctx, p)
	if err != nil {
		return err
	}
	j, ok, err := x.latestJob(ctx)
	if err != nil {
		return err
	}
	want := "none"
	if p.StandbyTried {
		want = "standby"
	}
	if ok && j.State == "done" {
		var r struct{ Mode string }
		if json.Unmarshal(j.Result, &r) != nil || r.Mode != want {
			return final("internal", fmt.Errorf("restore job %d: its stored result is out of shape", j.ID))
		}
		return x.patch(ctx, map[string]any{"mode": r.Mode})
	}
	if ok && j.Code == "tablespace" {
		return final("tablespace", fmt.Errorf("%s; this set cannot be restored: choose a target before its stop", j.Message))
	}
	if ok {
		cause, counted := jobCause(j)
		if p.Decided != nil && p.Decided.Job == j.ID {
			return &rewind{to: p.Decided.Target, cause: cause, counted: counted}
		}
		to, kv := "T5", map[string]any{}
		if j.Code == "history_mismatch" {
			onFollowed, err := x.setOn(ctx, p.Set, follow)
			if err != nil {
				return err
			}
			switch {
			case onFollowed && !p.StandbyTried:
				kv["standby_tried"] = true
			case p.From == "local":
				to, kv["from"], kv["standby_tried"] = "T5a", "offsite", false
				x.switched(p, kv, "the repository's history does not lead to the target (history_mismatch)")
			}
		}
		kv["decided"] = decision{j.ID, to}
		if err := x.patch(ctx, kv); err != nil {
			return err
		}
		return &rewind{to: to, cause: cause, counted: counted}
	}
	params := map[string]any{"set": p.Set, "mode": "none", "target_timeline": 0}
	if p.StandbyTried {
		params["mode"], params["target_timeline"] = "standby", follow
	}
	return x.submitParams(ctx, "restore", params)
}

// followed is the timeline the restore follows: the one named, else the
// newest recorded.
func (x *job) followed(ctx context.Context, p restoreParams) (int, error) {
	if p.Timeline > 0 {
		return p.Timeline, nil
	}
	tls, err := x.r.st.Timelines(ctx, x.op.Ref)
	return newestRecorded(tls), err
}

// setOn: the set lies on timeline tli.
func (x *job) setOn(ctx context.Context, label string, tli int) (bool, error) {
	sets, err := x.r.st.ListSets(ctx, x.op.Ref)
	i := slices.IndexFunc(sets, func(s store.BackupSet) bool { return s.Label == label })
	return err == nil && i >= 0 && sets[i].TLI == tli, err
}

// switched records, the first time only, why the source became the
// off-site store: the failure text keeps it.
func (x *job) switched(p restoreParams, kv map[string]any, why string) {
	if p.Switched == "" {
		kv["switched"] = why
	}
}

// toT3 rewinds to T3 — which stops the recovery start before anything reads
// the spool, wipes or restores — with kv written first; standby_tried is
// cleared (a new pass).
func (x *job) toT3(ctx context.Context, kv map[string]any, cause error, counted bool) error {
	if kv == nil {
		kv = map[string]any{}
	}
	kv["standby_tried"] = false
	// Its own bound: the step's may be spent (a re-key that ran out of time).
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := x.patch(wctx, kv); err != nil {
		return err
	}
	return &rewind{to: "T3", cause: cause, counted: counted}
}

// T7: the timeline this recovery will create chosen (BeginRecoveryAttempt)
// before each recover job; the job starts the recovery with the target
// rendered a third time and runs the serve job beside it. A failed or
// interrupted job goes back to T3 (target_not_reached off-site widens the
// fetch first). A done job: the last segment the serve job handed over and,
// for the end of the archive, the shortfall check.
func (x *job) restoreRecover(ctx context.Context) error {
	p, err := x.rp()
	if err != nil {
		return err
	}
	j, ok, err := x.latestJob(ctx)
	if err != nil {
		return err
	}
	if ok && j.State == "done" {
		return x.recovered(ctx, p, j)
	}
	if ok {
		cause, counted := jobCause(j)
		if p.Decided != nil && p.Decided.Job == j.ID {
			return &rewind{to: "T3", cause: cause, counted: counted}
		}
		kv := map[string]any{"decided": decision{j.ID, "T3"}}
		if j.Code == "target_not_reached" && p.From == "offsite" {
			kv["fetch_extra"] = p.FetchExtra + 1
		}
		return x.toT3(ctx, kv, cause, counted)
	}
	bs, err := x.r.st.GetBackupState(ctx, x.op.Ref)
	if err != nil {
		return err
	}
	_, err = x.r.st.BeginRecoveryAttempt(ctx, x.op.Ref, x.op.Ref+"-"+bs.Incarnation, x.op.ID, heldTimelines(p.Histories))
	if errors.Is(err, store.ErrTimelineConflict) {
		kv := map[string]any{"from": "offsite"}
		x.switched(p, kv, "a timeline's history is off-site but not in the repository (timeline_conflict)")
		return x.toT3(ctx, kv, &failure{code: "timeline_conflict", err: fmt.Errorf("%w; the restore reads the off-site store next", err)}, false)
	}
	if err != nil {
		return err
	}
	t, err := x.restoreTarget(ctx, p)
	if err != nil {
		return err
	}
	if err := x.patch(ctx, map[string]any{"t7_started": true}); err != nil {
		return err
	}
	target := map[string]any{"timeline": t.Timeline}
	if !t.Time.IsZero() {
		target["time"] = t.Time.UTC().Format(time.RFC3339Nano)
	}
	if t.LSN != "" {
		target["lsn"] = t.LSN
	}
	return x.submitParams(ctx, "recover", map[string]any{"target": target})
}

// recovered consumes a done recover job.
func (x *job) recovered(ctx context.Context, p restoreParams, j store.Job) error {
	var r struct {
		Promoted bool `json:"promoted"`
		Serve    *struct {
			LastSegment string `json:"last_segment"`
		} `json:"serve"`
	}
	if json.Unmarshal(j.Result, &r) != nil || !r.Promoted || r.Serve != nil && r.Serve.LastSegment != "" && !segmentRE.MatchString(r.Serve.LastSegment) {
		return final("internal", fmt.Errorf("recover job %d: its stored result is out of shape", j.ID))
	}
	reached := ""
	if r.Serve != nil {
		reached = r.Serve.LastSegment
	}
	kv := map[string]any{"reached_segment": reached}
	if p.To == "latest" {
		sf, err := x.shortfall(ctx, p, r.Serve != nil, reached)
		if err != nil {
			return err
		}
		kv["shortfall"] = sf
	}
	return x.patch(ctx, kv)
}

// shortfall compares, by segment number, the last segment the serve job
// handed to the recovery with the newest segment of the followed timeline
// as the last T4p push read it from repo/ (the record's on a replaced node's
// first pass). Below it: the figures, and a notice; the restore continues.
// Without either figure: "not checked", and a notice — never a silent pass.
func (x *job) shortfall(ctx context.Context, p restoreParams, served bool, reached string) (any, error) {
	tls, err := x.r.st.Timelines(ctx, x.op.Ref)
	if err != nil {
		return nil, err
	}
	follow := p.Timeline
	if follow == 0 {
		follow = newestRecorded(tls)
	}
	expected := ""
	if p.Newest == nil {
		if expected, err = x.r.st.NewestRecordedSegment(ctx, x.op.Ref, follow); err != nil {
			return nil, err
		}
	} else {
		expected = p.Newest[fmt.Sprintf("%08X", follow)]
	}
	why := ""
	switch {
	case !served:
		why = "the serve job left no result"
	case !segmentRE.MatchString(expected):
		why = fmt.Sprintf("no newest segment of timeline %d is known", follow)
	}
	if why != "" {
		x.notice(ctx, "restore-shortfall", "not checked: "+why)
		return "not checked", nil
	}
	base := reached
	if base == "" { // nothing handed over: the set's start is where replay began
		base = p.SetStart
	}
	got, exp := segNum(base), segNum(expected)
	if reached == "" && got > 0 {
		got--
	}
	if got >= exp {
		return nil, nil
	}
	sf := map[string]any{"expected": expected, "reached": reached, "segments": exp - got}
	x.notice(ctx, "restore-shortfall", fmt.Sprintf("the recovery replayed through segment %q; the repository held segments through %s: %d segments not replayed",
		reached, expected, exp-got))
	return sf, nil
}

// segNum is a segment's number: its last 16 hex digits.
func segNum(seg string) uint64 {
	if !segmentRE.MatchString(seg) {
		return 0
	}
	n, _ := strconv.ParseUint(seg[8:], 16, 64)
	return n
}

// notice raises a restore's notice; a failure is logged, not the step's.
func (x *job) notice(ctx context.Context, code, detail string) {
	if err := x.r.st.Notice(context.WithoutCancel(ctx), x.op.Ref, code, pgsock.Sanitize(detail, 256)); err != nil {
		x.r.log.Error("raising a notice", "op", x.op.ID, "ref", x.op.Ref, "code", code, "err", x.r.text(err))
	}
}

// T8: the re-key — the platform's verifiers on the promoted recovery start,
// which then reads its timeline — and the timeline confirmed: it must be the
// pending one this restore chose, which becomes recorded (t8_done in the same
// transaction); then the recovery start stopped. Any failure before t8_done
// goes back to T3 at the cost of an attempt; a mismatch also sends the
// restore off-site, with notice timeline-mismatch.
func (x *job) restoreRekey(ctx context.Context) error {
	if err := x.reload(ctx); err != nil {
		return err
	}
	p, err := x.rp()
	if err != nil {
		return err
	}
	if !p.T8Done {
		rc, err := x.recoverer()
		if err != nil {
			return err
		}
		// The spec the runner gave the recovery start (SpecFor's).
		s, err := x.r.SpecFor(ctx, x.op.Ref)
		if err != nil {
			return err
		}
		tli, kerr := rc.Rekey(ctx, s)
		var cerr error
		if kerr == nil {
			cerr = x.r.st.ConfirmTimeline(ctx, x.op.Ref, x.op.ID, tli)
		}
		// Every outcome stops the recovery start: promoted and, unless the
		// confirm went through, not re-keyed — past the attempts' limit no T3
		// would follow.
		// Within what is left of the step's deadline (at least a few seconds):
		// a re-key that ran out of time costs one attempt, not two.
		left := 5 * time.Second
		if dl, ok := ctx.Deadline(); ok {
			left = max(left, time.Until(dl))
		}
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), left)
		serr := x.r.ag.StopCluster(sctx, x.op.Ref)
		cancel()
		if serr != nil && (kerr != nil || cerr != nil) {
			x.r.log.Error("stopping the recovery start", "op", x.op.ID, "ref", x.op.Ref, "err", x.r.text(serr))
		}
		switch {
		case kerr != nil:
			return x.toT3(ctx, nil, kerr, false)
		case errors.Is(cerr, store.ErrConflict):
			msg := fmt.Sprintf("the re-keyed cluster reports timeline %d, not the timeline %d this restore created", tli, x.pending(ctx))
			x.notice(ctx, "timeline-mismatch", msg)
			kv := map[string]any{"from": "offsite"}
			x.switched(p, kv, "the re-keyed cluster reported another timeline (timeline_mismatch)")
			return x.toT3(ctx, kv, &failure{code: "timeline_mismatch", err: errors.New(msg)}, false)
		case cerr != nil:
			return cerr // the next attempt finds no recovery start: its re-key fails, back to T3
		}
		if err := x.reload(ctx); err != nil {
			return err
		}
		return serr
	}
	return x.r.ag.StopCluster(ctx, x.op.Ref)
}

// pending is the restore's pending timeline, 0 when there is none.
func (x *job) pending(ctx context.Context) int {
	tls, _ := x.r.st.Timelines(ctx, x.op.Ref)
	for _, t := range tls {
		if t.State == "pending" && t.OpID == x.op.ID {
			return t.TLI
		}
	}
	return 0
}

// T9: the normal start (phase B) and the operational check.
func (x *job) restoreStart(ctx context.Context) error {
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	if err := x.r.ag.EnsureCluster(ctx, s); err != nil {
		return err
	}
	return x.r.ag.VerifyCluster(ctx, s)
}

// T11: PostgREST, the active route and the end-to-end probe, fetch/
// removed, and the restore done (the slot freed in the same transaction) with its result, the
// project active — one transaction. A restore an earlier T11 finished is
// finished.
func (x *job) restoreFinish(ctx context.Context) error {
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	if err := x.r.ag.EnsurePostgREST(ctx, s); err != nil {
		return err
	}
	if err := x.expose(ctx, s); err != nil {
		return err
	}
	if err := x.r.ag.RemoveFetch(ctx, s); err != nil {
		return err
	}
	res, err := x.restoreResult(ctx)
	if err != nil {
		return err
	}
	if err := x.record(ctx); err != nil {
		return err
	}
	if err := x.r.st.FinishRestore(ctx, x.op.ID, res); errors.Is(err, store.ErrConflict) {
		if op, gerr := x.r.st.GetOperation(ctx, x.op.ID); gerr != nil || op.State != "done" {
			return err
		}
	} else if err != nil {
		return err
	}
	return errFinished
}

// restoreResult is the restore's result document.
func (x *job) restoreResult(ctx context.Context) (json.RawMessage, error) {
	p, err := x.rp()
	if err != nil {
		return nil, err
	}
	tls, err := x.r.st.Timelines(ctx, x.op.Ref)
	if err != nil {
		return nil, err
	}
	var created *int
	for _, t := range tls {
		if t.State == "recorded" && t.OpID == x.op.ID {
			created = &t.TLI
		}
	}
	type stepTime struct {
		Step    string `json:"step"`
		Seconds int    `json:"seconds"`
	}
	steps := []stepTime{}
	for _, s := range restoreOrder {
		if n, ok := p.Times[s.id]; ok {
			steps = append(steps, stepTime{s.id, n})
		}
	}
	shortfall := p.Shortfall
	if len(shortfall) == 0 {
		shortfall = json.RawMessage("null")
	}
	return json.Marshal(map[string]any{"to": p.To, "from": p.From, "set": p.Set, "mode": p.Mode,
		"reached_segment": p.Reached, "new_timeline": created, "previous_timeline": p.N,
		"previous_newest_segment": p.NNewest, "seeded": p.Seeded, "shortfall": shortfall, "steps": steps})
}

// restoreNote adds to the last_error of a restore that ends failed the state
// it leaves the project in and the commands that leave it.
func (x *job) restoreNote(ctx context.Context, msg string) string {
	// Only for the restore's own steps (the worker's tests run other tables under its kind).
	if x.op.Kind != "restore" || indexOf(tables["restore"], "T5") < 0 {
		return msg
	}
	proj, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return msg
	}
	p, err := x.rp()
	if err != nil {
		return msg
	}
	if p.Switched != "" && p.From == "offsite" { // the first cause, after the last one's code and text
		msg += " (read from the off-site store because " + p.Switched + ")"
	}
	var note string
	switch {
	case proj.State == "restoring" && (p.Wiped || p.Replaced && (p.Mode != "" || p.T7Started)):
		back := ""
		if p.N > 0 {
			back = fmt.Sprintf("; the state before it is 'supapace project restore %s --to latest --timeline %d'", x.op.Ref, p.N)
		}
		note = fmt.Sprintf("; the project stays restoring with its route draining (not served), its data directory replaced by "+
			"this restore: once the cause is removed, 'supapace op retry %d' continues%s; 'supapace project delete %s' removes "+
			"the project", x.op.ID, back, x.op.Ref)
	case proj.State == "restoring" && x.op.Step == "T1": // T2 did not finish: its route may not be draining yet
		note = fmt.Sprintf("; the project is restoring, its route possibly still active on its old data: 'supapace op retry %d' "+
			"continues this restore; 'supapace project delete %s' removes the project", x.op.ID, x.op.Ref)
	case proj.State == "restoring" && p.Replaced:
		note = fmt.Sprintf("; the project stays restoring, not served; nothing of it is on this node yet: 'supapace op retry %d' "+
			"continues this restore; 'supapace project delete %s' removes the project", x.op.ID, x.op.Ref)
	case proj.State == "restoring":
		note = fmt.Sprintf("; the project stays restoring with its route draining (not served), its data directory unchanged: "+
			"'supapace op retry %d' continues this restore; 'supapace project restore %s --to latest' brings it back as it was; "+
			"'supapace project delete %s' removes the project", x.op.ID, x.op.Ref, x.op.Ref)
	case p.Replaced:
		note = fmt.Sprintf("; nothing of the project is on this node yet; 'supapace op retry %d' continues", x.op.ID)
	case proj.State == "restarting":
		note = fmt.Sprintf("; the project is as the failed restart left it (not served); 'supapace project restore %s --to TARGET' "+
			"restores it with other options", x.op.Ref)
	default:
		note = fmt.Sprintf("; the project was not changed and is still served; 'supapace project restore %s --to TARGET' "+
			"restores it with other options", x.op.Ref)
	}
	return pgsock.Sanitize(msg, maxLastError-len(note)) + note
}

// completeCopy: j is a done replication job whose stored result is a copy
// that ended complete — not a rebuild page, not skipped, not stopped.
func completeCopy(j store.Job) bool {
	var r struct {
		Mode, Stopped, Skipped string
		Complete               bool
	}
	return j.State == "done" && json.Unmarshal(j.Result, &r) == nil && r.Complete && r.Stopped == "" && r.Skipped == "" && r.Mode == "copy"
}

// awaitFinal is a job step whose job fails final on codes no retry changes.
func (x *job) awaitFinal(ctx context.Context, kind, why string, codes ...string) error {
	j, ok, err := x.latestJob(ctx)
	if err == nil && ok && j.State == "failed" && slices.Contains(codes, j.Code) {
		return final(j.Code, fmt.Errorf("%s; %s", j.Message, why))
	}
	_, err = x.awaitJob(ctx, kind)
	return err
}
