package backup

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/Amphoze/supapace/internal/walname"
)

func init() {
	buildReplicate, recordReplicate = buildReplicateJob, recordReplicateJob
}

// Bounds of a replication result that jobio does not enforce by count; the
// runner checks them before anything is recorded.
const (
	maxProbeRows = 32
	maxNotices   = 16
	maxInfo      = 4
)

// infoNames are the four info files, with the tree each lies in.
var infoNames = map[string]string{"archive.info": "archive", "archive.info.copy": "archive",
	"backup.info": "backup", "backup.info.copy": "backup"}

// copyNotices are the notice codes a copy job may raise.
var copyNotices = map[string]bool{"unlisted-entry": true, "history-rewritten": true, "offsite-differs": true,
	"walk-truncated": true, "unreadable-entry": true, "segment-without-history": true}

// rebuildNotices are the notice codes a rebuild page may raise: a listed key
// outside the layout (a provider's folder object, a stray or planted key).
var rebuildNotices = map[string]bool{"unlisted-entry": true}

// maxNoticeDetail bounds a notice's detail as the job reports it; the store
// cleans it and keeps at most 256 bytes.
const maxNoticeDetail = 1024

// checkNotices: every notice of one of codes, its count not negative, its
// detail within its bound.
func checkNotices(ns []jobio.Notice, codes map[string]bool) error {
	for _, n := range ns {
		if !codes[n.Code] || n.Count < 0 || len(n.Detail) > maxNoticeDetail {
			return fmt.Errorf("notice %.32q (%d, %d bytes)", n.Code, n.Count, len(n.Detail))
		}
	}
	return nil
}

// raiseNotices records a job's notices, already checked against its kind's
// codes: one row per subject and code, its count raised by each (the store's
// upsert), with the last detail. The codes are written out (see noticeFailed).
func (r *Runner) raiseNotices(ctx context.Context, j store.Job, ns []jobio.Notice) {
	for _, n := range ns {
		text := fmt.Sprintf("job %d: %d: %s", j.ID, n.Count, n.Detail)
		var err error
		switch s := j.Subject; n.Code {
		case "unlisted-entry":
			err = r.st.Notice(ctx, s, "unlisted-entry", text)
		case "history-rewritten":
			err = r.st.Notice(ctx, s, "history-rewritten", text)
		case "offsite-differs":
			err = r.st.Notice(ctx, s, "offsite-differs", text)
		case "walk-truncated":
			err = r.st.Notice(ctx, s, "walk-truncated", text)
		case "unreadable-entry":
			err = r.st.Notice(ctx, s, "unreadable-entry", text)
		case "segment-without-history":
			err = r.st.Notice(ctx, s, "segment-without-history", text)
		default:
			err = fmt.Errorf("notice code %.32q is not one a job raises", n.Code)
		}
		r.noticeFailed(j.Subject, n.Code, err)
	}
}

var copyStops = map[string]bool{"": true, "caps": true, "budget": true, "upload-failed": true, "held": true}

// rebuilding: the subject's record is not yet rebuilt for the current epoch.
func (r *Runner) rebuilding(ctx context.Context, bs store.BackupState) (bool, int64, error) {
	epoch, err := r.st.Epoch(ctx)
	return bs.RebuildEpoch < epoch, epoch, err
}

// buildReplicateJob completes a replication job: a rebuild page from the
// markers stored now while the record lags the epoch, else a copy with the
// day's budget left. The memory follows the record's row count. A copy's
// index file is made to match the record first; a rebuild job mounts the file
// but never reads it (the last page rebuilds it), so it is only made when
// absent.
func buildReplicateJob(ctx context.Context, r *Runner, j store.Job, in *jobio.Input, spec *agent.JobSpec) error {
	bs, err := r.st.GetBackupState(ctx, j.Subject)
	if err != nil {
		return err
	}
	reb, _, err := r.rebuilding(ctx, bs)
	if err != nil {
		return err
	}
	if reb {
		rows, err := r.st.ObjectCount(ctx, j.Subject)
		if err == nil {
			if _, serr := os.Lstat(r.p.IndexFile(j.Subject)); serr != nil {
				err = r.rebuildIndex(ctx, j.Subject)
			}
		}
		if err != nil {
			return err
		}
		spec.MemMB = bklimit.ReplMemMB(rows)
		return buildRebuild(bs, in)
	}
	now := r.now()
	if bs.ReplPausedUntil != nil && now.Before(*bs.ReplPausedUntil) {
		return jobErr("budget", "replication is paused until "+bs.ReplPausedUntil.UTC().Format(time.RFC3339))
	}
	rows, err := r.ensureIndex(ctx, j.Subject)
	if err != nil {
		return err
	}
	spec.MemMB = bklimit.ReplMemMB(rows)
	left, leftObjects := int64(-1), -1 // the control plane has no budget
	if j.Subject != nodecfg.ControlPlaneSubject {
		bb, bo, err := r.budgets(ctx, j.Subject)
		if err != nil {
			return err
		}
		if bs.BudgetDay != nil && bs.BudgetDay.UTC().Format(time.DateOnly) == now.UTC().Format(time.DateOnly) {
			bb, bo = bb-bs.BytesToday, bo-bs.ObjectsToday
		}
		left, leftObjects = max(bb, 0), max(bo, 0)
	}
	// ponytail: the newest 256 versions are read; an info file not among them
	// is uploaded again as a new version, and is then the newest.
	vs, err := r.st.ListInfoVersions(ctx, j.Subject, 256)
	if err != nil {
		return err
	}
	sums := map[string]string{}
	for _, v := range vs {
		if _, seen := sums[v.Name]; !seen {
			sums[v.Name] = hex.EncodeToString(v.SHA256)
		}
	}
	in.Repl = &jobio.ReplInput{Mode: "copy", MaxFiles: bklimit.ReplMaxFiles, MaxEntries: bklimit.ReplMaxEntries,
		MaxBytes: bklimit.ReplMaxBytes, BudgetBytes: left, BudgetObjects: leftObjects, InfoSHA256: sums}
	return nil
}

// budgets are a project's daily upload budgets, its overrides included.
func (r *Runner) budgets(ctx context.Context, ref string) (int64, int, error) {
	p, err := r.st.GetProject(ctx, ref)
	if err != nil {
		return 0, 0, err
	}
	bb, bo := bklimit.Budgets(p.Config.DiskQuotaMB, p.Config.UploadMBPerDay, p.Config.UploadObjectsPerDay)
	return bb, bo, nil
}

// replStored is the document stored as a replication job's result: the
// result with its lists replaced by their counts; complete and mode kept.
type replStored struct {
	OK           bool   `json:"ok"`
	Mode         string `json:"mode"`
	Complete     bool   `json:"complete"`
	Stopped      string `json:"stopped"`
	Uploaded     int    `json:"uploaded"`
	Adopted      int    `json:"adopted"`
	Info         int    `json:"info"`
	SetsComplete int    `json:"sets_complete"`
	Rows         int    `json:"rows"`
	Notices      int    `json:"notices"`
	Bytes        int64  `json:"bytes"`
	Objects      int    `json:"objects"`
	Walked       int    `json:"walked"`
	Truncated    bool   `json:"truncated"`
	Held         int    `json:"held"`
	Last         bool   `json:"last"`
}

func stored(v jobio.ReplResult, complete bool) (json.RawMessage, error) {
	return jobio.MarshalResult(replStored{OK: true, Mode: v.Mode, Complete: complete, Stopped: v.Stopped,
		Uploaded: len(v.Uploaded), Adopted: len(v.Adopted), Info: len(v.Info), SetsComplete: len(v.SetsComplete),
		Rows: len(v.Rows), Notices: len(v.Notices), Bytes: v.Bytes, Objects: v.Objects, Walked: v.Walked,
		Truncated: v.Truncated, Held: v.Held, Last: v.Last})
}

// recordReplicateJob checks a replication result whole and records it: a
// copy's rows, info versions and sets, its notices and the budget; a rebuild
// page into the record. Anything out of bounds is an error (crashed), before
// any store write.
func recordReplicateJob(ctx context.Context, r *Runner, j store.Job, v jobio.ReplResult) (json.RawMessage, error) {
	if len(v.ProbeRows) > maxProbeRows || len(v.Notices) > maxNotices || len(v.Info) > maxInfo ||
		len(v.Uploaded)+len(v.Adopted) > bklimit.ReplMaxFiles { // and so uploaded ≤ 2,048
		return nil, fmt.Errorf("%d probe rows, %d notices, %d info versions, %d uploaded and %d adopted: above the job's bounds",
			len(v.ProbeRows), len(v.Notices), len(v.Info), len(v.Uploaded), len(v.Adopted))
	}
	if v.Bytes < 0 || v.Objects < 0 || v.Walked < 0 || v.Held < 0 {
		return nil, errors.New("a replication figure is negative")
	}
	bs, err := r.st.GetBackupState(ctx, j.Subject)
	if err != nil {
		return nil, err
	}
	reb, epoch, err := r.rebuilding(ctx, bs)
	if err != nil {
		return nil, err
	}
	if v.Mode == "rebuild" {
		return r.recordRebuild(ctx, j, v, bs, epoch)
	}
	if reb {
		return nil, errors.New("a copy result while the record is not rebuilt")
	}
	return r.recordCopy(ctx, j, v)
}

func (r *Runner) recordCopy(ctx context.Context, j store.Job, v jobio.ReplResult) (json.RawMessage, error) {
	if !copyStops[v.Stopped] {
		return nil, fmt.Errorf("stopped %.16q", v.Stopped)
	}
	s, err := r.subjectOf(ctx, j.Subject)
	if err != nil {
		return nil, err
	}
	// The record's own time, never the time a job reports: every restore decision
	// by time reads it.
	now := r.now()
	rows := make([]store.ObjectRow, 0, len(v.Uploaded)+len(v.Adopted))
	for _, l := range [][]jobio.Row{v.Uploaded, v.Adopted} {
		for _, x := range l {
			if err := uploadedKey(s, x); err != nil {
				return nil, err
			}
			sum, _ := hex.DecodeString(x.SHA256) // lower-case hex or empty: jobio's
			rows = append(rows, store.ObjectRow{Key: x.Key, Size: x.Size, SHA256: sum, Ino: x.Ino, CtimeNS: x.CtimeNS,
				VersionID: x.VersionID, UploadedAt: now})
		}
	}
	info := make([]store.InfoVersion, 0, len(v.Info))
	for _, x := range v.Info {
		sum, _ := hex.DecodeString(x.SHA256) // the name: one of four, the table's own check
		info = append(info, store.InfoVersion{Name: x.Name, VersionID: x.VersionID, SHA256: sum, UploadedAt: now})
	}
	if err := checkNotices(v.Notices, copyNotices); err != nil {
		return nil, err
	}
	// Segments held back for their history leave the replication incomplete,
	// whatever the job says; with no other stop the stop is "held", which fails
	// a replicate step (repeating cannot bring the history), as "caps" repeats it.
	complete := v.Complete && v.Held == 0
	if v.Held > 0 && v.Stopped == "" {
		v.Stopped = "held"
	}
	bb, bo := int64(0), 0 // none for the control plane
	if j.Subject != nodecfg.ControlPlaneSubject {
		if bb, bo, err = r.budgets(ctx, j.Subject); err != nil {
			return nil, err
		}
	}
	over, err := r.st.RecordUploads(ctx, j.Subject, store.Uploads{Rows: rows, Info: info, SetsComplete: v.SetsComplete,
		Complete: complete, BudgetBytes: bb, BudgetObjects: bo, At: now, Launch: j.Launch})
	if err != nil {
		return nil, err
	}
	// The record is written: what follows is logged, never the job's end.
	if len(v.Adopted) > 0 { // an adoption can fill a hash, which no count shows
		err = r.rebuildIndex(ctx, j.Subject)
	} else {
		idx := make([]jobio.IndexRow, len(v.Uploaded))
		for i, x := range v.Uploaded {
			idx[i] = jobio.IndexRow{Key: x.Key, Size: x.Size, Ino: x.Ino, CtimeNS: x.CtimeNS, SHA256: x.SHA256}
		}
		err = r.appendIndex(ctx, j.Subject, idx)
	}
	if err != nil {
		r.log.Error("writing an index file", "subject", j.Subject, "err", clean(err.Error()))
	}
	r.raiseNotices(ctx, j, v.Notices)
	if v.Held > 0 {
		r.noticeFailed(j.Subject, "segment-without-history",
			r.st.Notice(ctx, j.Subject, "segment-without-history", fmt.Sprintf("job %d: %d segments held back for their history", j.ID, v.Held)))
	}
	if over || v.Stopped == "budget" {
		r.pauseForBudget(ctx, j.Subject, now)
	}
	return stored(v, complete)
}

// uploadedKey checks a reported row against the subject's repository: a path
// the allow-list names for its stanza, of an admitted timeline, within its
// kind's size bound.
func uploadedKey(s subject, x jobio.Row) error {
	k, tli, _, ok := walname.RepoPath(s.stanza, x.Key)
	if !ok {
		return fmt.Errorf("key %.64q is not a repository path of the subject", x.Key)
	}
	bound := int64(bklimit.SetFileMax)
	switch k {
	case walname.Segment:
		bound = bklimit.SegmentMax
	case walname.History, walname.Label, walname.Info:
		bound = bklimit.SmallMax
	}
	if (k == walname.Segment || k == walname.History || k == walname.Label) && s.admitted != nil && !walname.Admitted(tli, s.admitted) {
		return fmt.Errorf("key %.64q is of a timeline not admitted", x.Key)
	}
	if x.Size > bound {
		return fmt.Errorf("key %.64q: %d bytes, above its kind's bound", x.Key, x.Size)
	}
	return nil
}

// noticeFailed logs err, a failed raise of notice code (the store cleans and
// cuts a notice's text). Each raise names its code as a literal, so that a
// reader of the source finds every code the runner raises.
func (r *Runner) noticeFailed(subject, code string, err error) {
	if err != nil {
		r.log.Error("raising a backup notice", "subject", subject, "code", code, "err", clean(err.Error()))
	}
}

// pauseForBudget pauses the subject's replication until the next 00:00 UTC
// and raises budget-exceeded with the projected time until the repository
// quota fills: its free space over the day's upload rate.
func (r *Runner) pauseForBudget(ctx context.Context, subject string, now time.Time) {
	y, m, d := now.UTC().Date()
	midnight := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	until := midnight.AddDate(0, 0, 1)
	if err := r.st.PauseReplication(ctx, subject, until); err != nil {
		r.log.Error("pausing a replication", "subject", subject, "err", clean(err.Error()))
	}
	fill := "unknown"
	if bs, err := r.st.GetBackupState(ctx, subject); err == nil && bs.RepoHardKB != nil && bs.RepoUsedKB != nil && bs.BytesToday > 0 {
		rate := float64(bs.BytesToday) / max(now.Sub(midnight).Seconds(), 1)
		free := float64(max(*bs.RepoHardKB-*bs.RepoUsedKB, 0)) * 1024
		fill = (time.Duration(min(free/rate, 1e9)) * time.Second).Round(time.Minute).String() // at most ~31 years
	}
	text := fmt.Sprintf("replication paused until %s; at today's upload rate the repository quota fills in %s", until.Format(time.RFC3339), fill)
	r.noticeFailed(subject, "budget-exceeded", r.st.Notice(ctx, subject, "budget-exceeded", text))
}
