package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bkjob"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/repl"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/Amphoze/supapace/internal/walname"
)

// outcome is how a job ends: its state, a failure's code and message, and
// the document stored as its result.
type outcome struct {
	state, code, msg string
	result           json.RawMessage
}

func failed(code, msg string) outcome { return outcome{state: "failed", code: code, msg: msg} }

// crashed is a result the runner does not use: unparsable, out of shape, or
// one the store refuses.
func crashed(err error) outcome { return failed("crashed", "result refused: "+err.Error()) }

// hostStateText is agent.ErrHostState's text, matched along the chain:
// a mount source the launcher refused, recorded as host_state.
const hostStateText = "agent: a job's mount source is not as the platform made it"

func isHostState(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if err.Error() == hostStateText {
			return true
		}
	}
	return false
}

// runnerCodes are the codes the runner or the store assigns, and the codes of
// an operation's step: a job's own failure document never carries one. Some
// count no attempt (cancelled, interrupted), so a job that could claim them
// would make its operation retry for ever. A kind whose program lists its
// codes (bkjob.Codes) takes those and no other; this deny-list holds for the
// kinds whose programs list none yet.
var runnerCodes = map[string]bool{"deadline": true, "interrupted": true, "cancelled": true, "crashed": true,
	"host_state": true, "record_not_rebuilt": true, "fetch_too_large": true, "internal": true, "recovered": true,
	"recovery_failed": true, "target_not_reached": true, "interrupted_limit": true}

// jobCode reports whether a job of kind may end with its own failure code.
func jobCode(kind, code string) bool {
	if codes, ok := bkjob.Codes(kind); ok {
		return slices.Contains(codes, code)
	}
	if codes := repl.Codes(kind); codes != nil {
		return slices.Contains(codes, code)
	}
	return !runnerCodes[code]
}

var (
	tliKeyRE = regexp.MustCompile(`^[0-9A-F]{8}$`)
	labelRE  = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}F$`)
	lsnRE    = regexp.MustCompile(`^[0-9A-F]{1,8}/[0-9A-F]{1,8}$`)
	segRE    = regexp.MustCompile(`^[0-9A-F]{24}$`)
	reasons  = map[string]bool{"timeline": true, "shape": true, "refused-44": true, "refused-45": true, "refused-46": true}
)

// record turns what the launcher returned into the job's end: the result is
// parsed first and every field the store will take is checked before
// anything is written. What is stored is the parsed value re-encoded, never
// the line as received.
func (r *Runner) record(ctx context.Context, j store.Job, s subject, res agent.JobResult, runErr error) outcome {
	switch {
	case runErr != nil && isHostState(runErr):
		return failed("host_state", runErr.Error())
	case runErr != nil:
		return failed("internal", "launch: "+runErr.Error())
	case res.TimedOut:
		return failed("deadline", "the job ran past its deadline and was killed")
	case len(res.Result) == 0:
		return failed("crashed", fmt.Sprintf("the job left no result line (exit %d)", res.ExitCode))
	}
	v, fail, err := jobio.ParseResult(j.Kind, res.Result)
	switch {
	case err != nil:
		return crashed(err)
	case fail != nil && res.ExitCode != 1, fail == nil && res.ExitCode != 0:
		return failed("crashed", fmt.Sprintf("exit %d does not match the result", res.ExitCode))
	case fail != nil && !jobCode(j.Kind, fail.Code):
		return failed("crashed", "the job claimed a code its kind does not end with: "+fail.Code)
	case fail != nil:
		r.failureNotice(ctx, j, fail.Code)
		return failed(fail.Code, fail.Message)
	}
	var stored json.RawMessage
	switch x := v.(type) {
	case jobio.ReplResult:
		if recordReplicate == nil {
			return failed("internal", "this node does not record replicate jobs yet")
		}
		stored, err = recordReplicate(ctx, r, j, x)
	case jobio.FetchResult:
		if recordFetch == nil {
			return failed("internal", "this node does not record fetch jobs yet")
		}
		stored, err = recordFetch(ctx, r, j, x)
	default:
		err = r.recordWorker(ctx, j, s, v)
		if err == nil {
			stored, err = jobio.MarshalResult(v)
		}
	}
	if err != nil {
		return crashed(err)
	}
	return outcome{state: "done", result: stored}
}

// failureNotice raises the notice a failed job names: a full repository
// quota (only a push can tell it) and a failed backup.
func (r *Runner) failureNotice(ctx context.Context, j store.Job, code string) {
	n := ""
	switch {
	case code == "repository_quota":
		n = "repo-quota-full"
	case j.Kind == "backup":
		n = "backup-failed"
	}
	if n != "" {
		if err := r.st.Notice(ctx, j.Subject, n, fmt.Sprintf("job %d: %s", j.ID, code)); err != nil {
			r.log.Error("raising a backup notice", "subject", j.Subject, "code", n, "err", clean(err.Error()))
		}
	}
}

// recordWorker records a done worker job: its push (also the one nested in
// stanza-create, check and backup), a backup's set, the stanza and timeline
// 1 of a stanza-create, the seeding of a seed.
func (r *Runner) recordWorker(ctx context.Context, j store.Job, s subject, v any) error {
	var push *jobio.PushResult
	var set *store.BackupSet
	switch x := v.(type) {
	case jobio.PushResult:
		push = &x
	case jobio.CheckJobResult:
		push = x.Push
	case jobio.RestoreResult:
		if x.Mode != "none" && x.Mode != "standby" {
			return fmt.Errorf("restore mode %.16q", x.Mode)
		}
	case jobio.SeedResult:
		if x.Files < 0 || x.Bytes < 0 {
			return errors.New("a seed figure is negative")
		}
	case jobio.BackupResult:
		push = x.Push
		b, err := backupSet(j, x)
		if err != nil {
			return err
		}
		set = &b
	}
	var pr store.PushRecord
	if push != nil {
		var err error
		if pr, err = r.pushRecord(*push, s.admitted); err != nil {
			return err
		}
		if q, err := r.ag.QuotaUse(ctx, s.uid); err != nil {
			r.log.Error("reading quota use", "subject", s.name, "err", clean(err.Error()))
		} else {
			pr.Quota = &store.QuotaUse{DiskUsedKB: q.DiskUsedKB, DiskHardKB: q.DiskHardKB, RepoUsedKB: q.RepoUsedKB, RepoHardKB: q.RepoHardKB}
		}
		if err := r.st.RecordPush(ctx, j.Subject, pr); err != nil {
			return err
		}
	}
	var err error
	switch {
	case set != nil:
		err = r.st.RecordSet(ctx, *set)
	case j.Kind == "stanza-create":
		err = r.st.MarkStanza(ctx, j.Subject)
	case j.Kind == "seed":
		err = r.st.SetSeeded(ctx, j.Subject, r.now())
	}
	if err == nil && len(pr.Gaps) > 0 {
		r.forcedFull(ctx, s)
	}
	if err == nil && (j.Kind == "push" || j.Kind == "backup") {
		r.queueReplicate(ctx, s)
	}
	return err
}

// pushRecord checks every member of a push result that is stored — the job's
// row keeps it re-encoded and the backup state its figures — and builds the
// record. newest: each key a timeline of 8 upper-case hex digits that the
// subject admits (nil: the control plane, every one), each value a segment of
// that timeline; the segment recorded is the highest timeline's. first and
// last: empty or a spool name; histories: at most 64 history names (one per
// timeline newest may name); quarantined names: 1 to 255 bytes (a file name)
// without a control byte, with a known reason; figures not negative, the
// pushed count at most the job's entry cap, the spool entries within their
// column.
func (r *Runner) pushRecord(p jobio.PushResult, admitted []uint32) (store.PushRecord, error) {
	if p.Pushed < 0 || p.Pushed > bklimit.PushMaxEntries || p.Remaining < 0 || p.OtherEntries < 0 ||
		p.SpoolEntries < 0 || p.SpoolEntries > math.MaxInt32 || p.SpoolBytes < 0 {
		return store.PushRecord{}, errors.New("a push figure is out of range")
	}
	if !spoolName(p.First, walname.None) || !spoolName(p.Last, walname.None) || len(p.Histories) > maxHistories {
		return store.PushRecord{}, errors.New("first, last or histories out of shape")
	}
	for _, h := range p.Histories {
		if h == "" || !spoolName(h, walname.History) {
			return store.PushRecord{}, fmt.Errorf("history %.32q", h)
		}
	}
	rec := store.PushRecord{Complete: p.Complete, Pushed: p.Pushed, SpoolEntries: p.SpoolEntries,
		SpoolBytes: p.SpoolBytes, SpoolOldest: p.SpoolOldest, At: r.now()}
	var top uint64
	for k, seg := range p.Newest {
		t, err := strconv.ParseUint(k, 16, 32)
		kind, tli, ok := walname.Spool(seg)
		if !tliKeyRE.MatchString(k) || err != nil || !ok || kind != walname.Segment || uint64(tli) != t ||
			admitted != nil && !walname.Admitted(tli, admitted) {
			return rec, fmt.Errorf("newest entry %.16q: %.32q is not a segment of an admitted timeline", k, seg)
		}
		if t >= top {
			top, rec.NewestSegment = t, seg
		}
	}
	for _, q := range p.Quarantined {
		if !reasons[q.Reason] || q.Name == "" || len(q.Name) > 255 || hasControl(q.Name) {
			return rec, fmt.Errorf("quarantined entry %.32q (%.32q)", q.Name, q.Reason)
		}
		rec.Gaps = append(rec.Gaps, store.Gap{Cause: "quarantine", First: q.Name, Last: q.Name, Detail: q.Reason + ": " + q.Name})
	}
	return rec, nil
}

// backupSet checks a backup result's set and builds its record.
func backupSet(j store.Job, b jobio.BackupResult) (store.BackupSet, error) {
	if !labelRE.MatchString(b.Label) || b.Timeline < 1 || b.Timeline > 1<<31-1 ||
		!segRE.MatchString(b.StartSegment) || !segRE.MatchString(b.StopSegment) ||
		!lsnRE.MatchString(b.StartLSN) || !lsnRE.MatchString(b.StopLSN) {
		return store.BackupSet{}, fmt.Errorf("backup set %.32q is out of shape", b.Label)
	}
	return store.BackupSet{Subject: j.Subject, Label: b.Label, TLI: int(b.Timeline), StartSegment: b.StartSegment,
		StopSegment: b.StopSegment, StartLSN: b.StartLSN, StopLSN: b.StopLSN, StartAt: b.Start, StopAt: b.Stop, JobID: j.ID}, nil
}

// forcedFull queues the subject's one forced full backup of the day (UTC)
// after a quarantine.
//
// ponytail: the day is taken before the job is queued; a failed submit loses
// that day's forced full (logged). Queue first if that ever matters.
func (r *Runner) forcedFull(ctx context.Context, s subject) {
	ok, err := r.st.MarkForcedFull(ctx, s.name, r.now())
	if err == nil && ok {
		_, err = r.submit(ctx, s.name, "backup", s.diskMB, s.repoMB)
	}
	if err != nil {
		r.log.Error("queueing a forced full backup", "subject", s.name, "err", clean(err.Error()))
	}
}

// maxHistories bounds a push's histories: one per timeline its newest map
// may name (jobio's bound of 64).
const maxHistories = 64

// spoolName: name is empty, or a spool name — of kind want unless want is
// walname.None (any kind).
func spoolName(name string, want walname.Kind) bool {
	if name == "" {
		return true
	}
	k, _, ok := walname.Spool(name)
	return ok && (want == walname.None || k == want)
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// queueReplicate queues a replication after a push or a backup was recorded
// done, with the store declared, unless one is queued or running: decided
// here, so that no tick has to walk the job table for it.
func (r *Runner) queueReplicate(ctx context.Context, s subject) {
	if r.Offsite() != "declared" {
		return
	}
	if bs, err := r.st.GetBackupState(ctx, s.name); err == nil && bs.ReplPausedUntil != nil && r.now().Before(*bs.ReplPausedUntil) {
		return // paused for its budget: the first push after the pause queues it
	}
	j, ok, err := r.ts.LastJob(ctx, s.name, "replicate")
	if err == nil && !(ok && busy(j)) {
		_, err = r.submit(ctx, s.name, "replicate", s.diskMB, s.repoMB)
	}
	if err != nil {
		r.log.Error("queueing a replication", "subject", s.name, "err", clean(err.Error()))
	}
}
