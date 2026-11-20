package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/Amphoze/supapace/internal/walname"
)

func init() {
	buildFetch, recordFetch = buildFetchJob, recordFetchJob
}

// fetchParams are a fetch job's parameters, written by the restore:
// {"set":"<label>","to":"latest"|"<RFC 3339>"|"lsn:<hex>/<hex>","timeline":N,"extra":N}.
// The plan takes every admitted timeline whatever timeline is targeted, so
// timeline is read for its shape only.
type fetchParams struct {
	Set      string `json:"set"`
	To       string `json:"to"`
	Timeline int    `json:"timeline"`
	Extra    int    `json:"extra"`
}

// target is a fetch's end: the whole archive, through a segment position, or
// up to a time.
type target struct {
	latest bool
	pos    string // the 16 hex digits of the segment holding the position
	time   time.Time
}

func parseFetchParams(b []byte) (fetchParams, target, error) {
	var p fetchParams
	var t target
	err := strictObject(b, &p, "set", "to", "timeline", "extra")
	if err == nil && (p.Timeline < 0 || p.Extra < 0) {
		err = errors.New("timeline or extra out of shape") // the set: looked up in the record
	}
	if err == nil {
		t, err = parseTarget(p.To)
	}
	if err != nil {
		return p, t, fmt.Errorf("fetch job parameters: %w", err)
	}
	return p, t, nil
}

func parseTarget(to string) (target, error) {
	if to == "latest" {
		return target{latest: true}, nil
	}
	if l, ok := strings.CutPrefix(to, "lsn:"); ok {
		hi, lo, ok := strings.Cut(l, "/")
		h, err1 := strconv.ParseUint(hi, 16, 32)
		o, err2 := strconv.ParseUint(lo, 16, 32)
		if !ok || !paramLSNRE.MatchString(l) || err1 != nil || err2 != nil {
			return target{}, fmt.Errorf("position %.32q", to)
		}
		// A segment is 16 MiB: the high word is the log, the low word's top byte the segment.
		return target{pos: fmt.Sprintf("%08X%08X", h, o>>24)}, nil
	}
	t, err := time.Parse(time.RFC3339, to)
	if err != nil {
		return target{}, fmt.Errorf("target %.40q", to)
	}
	return target{time: t}, nil
}

// archiveTimeout is the project's archive_timeout: its setting (no unit, s or
// min), else the default of 300 s. A value that does not parse — the
// configuration's own check refuses one — takes the longest allowed, 3600 s:
// the wider margin.
func archiveTimeout(gucs map[string]string) time.Duration {
	v, ok := gucs["archive_timeout"]
	if !ok {
		return 300 * time.Second
	}
	unit := time.Second
	if n, ok := strings.CutSuffix(v, "min"); ok {
		v, unit = n, time.Minute
	} else {
		v = strings.TrimSuffix(v, "s")
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 3600 || len(v) > 4 || strings.Trim(v, "0123456789") != "" {
		return 3600 * time.Second
	}
	return min(time.Duration(n)*unit, 3600*time.Second)
}

// plan is a fetch plan: its rows, the history names among them, their bytes.
type plan struct {
	rows      []jobio.PlanRow
	histories []string
	bytes     int64
}

func (p *plan) add(key, version string, sum []byte, size int64) {
	p.rows = append(p.rows, jobio.PlanRow{Key: key, VersionID: version, SHA256: hex.EncodeToString(sum), Size: size})
	p.bytes = min(p.bytes, math.MaxInt64-size) + size // sizes are not negative: it saturates
}

// fetchPlan builds the plan of a restore from the off-site record, by the
// record's own times only, never the object store's clock:
//   - the set's files, and every other set's files recorded at or before the
//     set's listed_at;
//   - each info file at its newest recorded version at or before listed_at;
//   - the history of every admitted timeline the record holds one for, in
//     whatever state — without an abandoned timeline's history the next
//     recovery could promote that number again;
//   - the archive files of the admitted timelines from the set's start
//     segment: all for latest, through the segment holding a position, and
//     for a time every file uploaded up to it plus the margin, and one
//     segment more per timeline.
//
// Each row is planned by its recorded version id (none: the oldest version)
// and hash (none for a rebuilt row). Refused while the record lags the epoch
// (record_not_rebuilt) and above the project's repository quota
// (fetch_too_large, with a notice).
func (r *Runner) fetchPlan(ctx context.Context, s subject, gucs map[string]string, p fetchParams, t target) (plan, error) {
	var pl plan
	bs, err := r.st.GetBackupState(ctx, s.name)
	if err != nil {
		return pl, err
	}
	if reb, _, err := r.rebuilding(ctx, bs); err != nil || reb {
		if err == nil {
			err = jobErr("record_not_rebuilt", "the off-site record is not rebuilt for this epoch yet")
		}
		return pl, err
	}
	sets, err := r.st.ListSets(ctx, s.name)
	if err != nil {
		return pl, err
	}
	i := slices.IndexFunc(sets, func(b store.BackupSet) bool { return b.Label == p.Set })
	if i < 0 || sets[i].ListedAt == nil {
		return pl, jobErr("internal", "backup set "+p.Set+" is not completely off-site")
	}
	set, listed := sets[i], *sets[i].ListedAt
	start := set.StartSegment[8:]
	var cut *time.Time
	if !t.latest && t.pos == "" {
		if m := bklimit.FetchMargin(archiveTimeout(gucs), p.Extra); m != bklimit.WholeArchive {
			c := t.time.Add(m)
			cut = &c
		}
	}
	next := map[uint32]store.ObjectRow{} // per timeline, the lowest segment past the time cut
	hist := map[string]bool{}
	err = r.st.ObjectRows(ctx, s.name, func(o store.ObjectRow) error {
		k, tli, label, ok := walname.RepoPath(s.stanza, o.Key)
		base := path.Base(o.Key)
		switch {
		case !ok || k == walname.Info:
			// Info files come from their recorded versions alone.
		case k == walname.History:
			if walname.Admitted(tli, s.admitted) {
				pl.add(o.Key, o.VersionID, o.SHA256, o.Size)
				hist[base] = true
			}
		case k == walname.Segment || k == walname.Label:
			pos := base[8:24]
			switch {
			case !walname.Admitted(tli, s.admitted) || pos < start || t.pos != "" && pos > t.pos:
			case cut != nil && o.UploadedAt.After(*cut):
				if n, seen := next[tli]; k == walname.Segment && (!seen || pos < path.Base(n.Key)[8:24]) {
					next[tli] = o
				}
			default:
				pl.add(o.Key, o.VersionID, o.SHA256, o.Size)
			}
		default: // a set's file
			if label == set.Label || !o.UploadedAt.After(listed) {
				pl.add(o.Key, o.VersionID, o.SHA256, o.Size)
			}
		}
		return nil
	})
	if err != nil {
		return pl, err
	}
	for _, o := range next {
		pl.add(o.Key, o.VersionID, o.SHA256, o.Size)
	}
	// ponytail: the newest 10,000 info versions (one each time an info file
	// changes); an older listed_at than they reach plans no info file.
	vs, err := r.st.ListInfoVersions(ctx, s.name, 10000)
	if err != nil {
		return pl, err
	}
	taken := map[string]bool{}
	for _, v := range vs { // newest first
		if tree, ok := infoNames[v.Name]; ok && !taken[v.Name] && !v.UploadedAt.After(listed) {
			taken[v.Name] = true
			// The record keeps no size for an info version: its kind's bound.
			pl.add(tree+"/"+s.stanza+"/"+v.Name, v.VersionID, v.SHA256, bklimit.SmallMax)
		}
	}
	for h := range hist {
		pl.histories = append(pl.histories, h)
	}
	slices.Sort(pl.histories)
	if quota := int64(s.repoMB) << 20; pl.bytes > quota {
		msg := fmt.Sprintf("the plan of set %s holds %d bytes, above the repository quota of %d MiB", p.Set, pl.bytes, s.repoMB)
		r.noticeFailed(s.name, "fetch-too-large", r.st.Notice(ctx, s.name, "fetch-too-large", msg))
		return pl, jobErr("fetch_too_large", msg)
	}
	return pl, nil
}

// planned is what a fetch job's record takes from its plan, kept from the
// launch: one entry per runner and subject, whose slot the job holds.
type planned struct {
	job       int64
	files     int
	maxBytes  int64
	histories []string
}

type plannedKey struct {
	r       *Runner
	subject string
}

var plans = struct {
	sync.Mutex
	m map[plannedKey]planned
}{m: map[plannedKey]planned{}}

// buildFetchJob builds the plan into /job/plan, sets the byte limit to the
// repository quota and, immediately before the launch, the replicator's
// quota to twice the largest repository quota. The control plane's fetch is
// recover's, never the runner's.
func buildFetchJob(ctx context.Context, r *Runner, j store.Job, in *jobio.Input, spec *agent.JobSpec) error {
	if j.Subject == nodecfg.ControlPlaneSubject {
		return jobErr("internal", "the control plane is fetched by recover only")
	}
	p, t, err := parseFetchParams(j.Params)
	if err != nil {
		return jobErr("internal", err.Error())
	}
	s, err := r.subjectOf(ctx, j.Subject)
	if err != nil {
		return err
	}
	proj, err := r.st.GetProject(ctx, j.Subject)
	if err != nil {
		return err
	}
	pl, err := r.fetchPlan(ctx, s, proj.Config.GUC, p, t)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := jobio.WritePlan(&buf, pl.rows); err != nil {
		return err
	}
	_, maxMB, err := r.st.RepoQuotaTotals(ctx)
	if err != nil {
		return err
	}
	if err := r.ag.SetReplicatorQuota(ctx, 2*maxMB); err != nil {
		return err
	}
	in.MaxBytes = int64(s.repoMB) << 20
	if spec.Files == nil {
		spec.Files = map[string][]byte{}
	}
	spec.Files["plan"] = buf.Bytes()
	plans.Lock()
	plans.m[plannedKey{r, j.Subject}] = planned{job: j.ID, files: len(pl.rows), maxBytes: in.MaxBytes, histories: pl.histories}
	plans.Unlock()
	return nil
}

// recordFetchJob stores a fetch's result with the histories of the plan the
// runner built — never anything the job reports of them. The counts are
// bounded by the plan.
func recordFetchJob(ctx context.Context, r *Runner, j store.Job, v jobio.FetchResult) (json.RawMessage, error) {
	plans.Lock()
	k := plannedKey{r, j.Subject}
	pl, ok := plans.m[k]
	if ok && pl.job == j.ID {
		delete(plans.m, k)
	}
	plans.Unlock()
	switch {
	case !ok || pl.job != j.ID:
		return nil, errors.New("no plan of this fetch job")
	case v.Files < 0 || v.Files > pl.files || v.Bytes < 0 || v.Bytes > pl.maxBytes:
		return nil, errors.New("fetched files or bytes beyond the plan")
	case v.NewestSegment != "" || v.NewestSet != "":
		return nil, errors.New("a project's fetch reports no newest segment or set")
	}
	return jobio.MarshalResult(jobio.FetchResult{OK: true, Files: v.Files, Bytes: v.Bytes, Histories: pl.histories})
}
