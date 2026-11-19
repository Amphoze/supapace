package adminapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

// DefaultLayout is the layout a create gets and a restart raises a project
// to: 1, a project without backups, as built; 2, with backups. Layout 1 is
// stored as 0 (the member omitted), so a configuration stored at layout 1 is
// the one stored before layouts existed.
var DefaultLayout = 1

// now is the clock of the lag figures and the day counters; tests replace it.
var now = time.Now

const (
	maxSets          = 64
	maxInfoVersions  = 16
	maxGaps          = 64
	maxNotices       = 32
	maxRestores      = 16
	maxTimeline      = 1<<31 - 1
	maxUploadMB      = maxDiskQuotaMB
	maxUploadObjects = 1 << 24
	maxTarget        = 64 // a restore target's bytes
)

// lsnRE is a WAL position, with or without its "lsn:" prefix.
var lsnRE = regexp.MustCompile(`^(lsn:)?[0-9A-Fa-f]{1,8}/[0-9A-Fa-f]{1,8}$`)

// layoutOf is a configuration's layout: 0 is 1.
func layoutOf(c store.ProjectConfig) int { return max(c.Layout, 1) }

// stored is how a layout is stored: 1 as 0.
func stored(layout int) int {
	if layout <= 1 {
		return 0
	}
	return layout
}

// devNode reports whether the development marker, a regular file beside
// node.json, exists.
func (a *api) devNode() bool {
	fi, err := os.Lstat(filepath.Join(filepath.Dir(a.paths.NodeJSON()), "dev-mode"))
	return err == nil && fi.Mode().IsRegular()
}

// offsite is the off-site declaration's state when the daemon's Ops tells
// it; an Ops without the method, or an answer outside the three states, is
// undeclared.
func (a *api) offsite() string {
	if o, ok := a.ops.(interface{ Offsite() string }); ok {
		if s := o.Offsite(); s == "declared" || s == "partial" {
			return s
		}
	}
	return "undeclared"
}

// uploadSettings checks the daily upload overrides a request gives: each 0
// (the default) to its maximum.
func uploadSettings(mb, objects *int) error {
	for _, s := range []struct {
		name string
		v    *int
		max  int
	}{{"upload_mb_per_day", mb, maxUploadMB}, {"upload_objects_per_day", objects, maxUploadObjects}} {
		if s.v != nil && (*s.v < 0 || *s.v > s.max) {
			return badRequest("%s must be 0 (the default) to %d", s.name, s.max)
		}
	}
	return nil
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// ───────── shapes ─────────

type windowJSON struct {
	Earliest *string `json:"from"`
	Latest   *string `json:"to"`
}

type setJSON struct {
	Label        string  `json:"label"`
	Timeline     int     `json:"timeline"`
	Start        string  `json:"start"`
	Stop         string  `json:"stop"`
	StartSegment string  `json:"start_segment"`
	StopSegment  string  `json:"stop_segment"`
	Replicated   bool    `json:"replicated"`
	ListedAt     *string `json:"listed_at"`
}

type pushJSON struct {
	LastOK        *string `json:"last_ok"`
	LagSeconds    *int64  `json:"lag_seconds"`
	SpoolEntries  *int    `json:"spool_entries"`
	SpoolBytes    *int64  `json:"spool_bytes"`
	SpoolOldest   *string `json:"spool_oldest"`
	NewestSegment *string `json:"newest_segment"`
}

type quotaJSON struct {
	Taken       string `json:"at"`
	DiskUsedMB  int64  `json:"disk_used_mb"`
	DiskQuotaMB int64  `json:"disk_quota_mb"`
	RepoUsedMB  int64  `json:"repo_used_mb"`
	RepoQuotaMB int64  `json:"repo_quota_mb"`
}

type replicationJSON struct {
	Declared        string  `json:"declared"`
	LastOK          *string `json:"last_ok"`
	LagSeconds      *int64  `json:"lag_seconds"`
	PausedUntil     *string `json:"paused_until"`
	Rebuilding      bool    `json:"rebuilding"`
	BytesToday      int64   `json:"bytes_today"`
	BytesBudget     int64   `json:"bytes_budget"`
	ObjectsToday    int     `json:"objects_today"`
	ObjectsBudget   int     `json:"objects_budget"`
	ObjectsRecorded int64   `json:"objects_recorded"`
}

type infoVersionJSON struct {
	Name      string `json:"name"`
	VersionID string `json:"version_id"`
	At        string `json:"at"`
	SHA256    string `json:"sha256"`
}

type timelineJSON struct {
	Timeline    int    `json:"timeline"`
	State       string `json:"state"`
	OperationID *int64 `json:"operation_id"`
}

type gapJSON struct {
	Cause        string `json:"cause"`
	FirstSegment string `json:"first_segment"`
	LastSegment  string `json:"last_segment"`
	At           string `json:"at"`
	Detail       string `json:"detail"`
}

type noticeJSON struct {
	Code    string `json:"code"`
	Count   int64  `json:"count"`
	FirstAt string `json:"first_at"`
	LastAt  string `json:"last_at"`
	Detail  string `json:"detail"`
}

type restoreJSON struct {
	OperationID int64   `json:"operation_id"`
	State       string  `json:"state"`
	To          string  `json:"to"`
	From        string  `json:"from"`
	NewTimeline *int    `json:"new_timeline"`
	FinishedAt  *string `json:"finished_at"`
}

// backupsJSON is the backups document. Without a backup state row (layout 1,
// or a create that has not reached it) stanza, incarnation, push, quota and
// replication are null and the lists empty.
type backupsJSON struct {
	Ref          string            `json:"ref"`
	Stanza       *string           `json:"stanza"`
	Incarnation  *string           `json:"incarnation"`
	Layout       int               `json:"layout"`
	Sets         []setJSON         `json:"sets"`
	Window       windowJSON        `json:"window"`
	Push         *pushJSON         `json:"push"`
	Quota        *quotaJSON        `json:"quota"`
	Replication  *replicationJSON  `json:"replication"`
	InfoVersions []infoVersionJSON `json:"info_versions"`
	Timelines    []timelineJSON    `json:"timelines"`
	Gaps         []gapJSON         `json:"gaps"`
	Notices      []noticeJSON      `json:"notices"`
	Restores     []restoreJSON     `json:"restores"`
}

// outOfWindowJSON is the error body of a restore target outside the window.
type outOfWindowJSON struct {
	errorJSON
	Window windowJSON `json:"window"`
}

// text cleans a text the store holds for the document.
func text(s string) string { return pgsock.Sanitize(s, maxDetail) }

// lag is the whole seconds from t to now, null without t.
func lag(t *time.Time) *int64 {
	if t == nil {
		return nil
	}
	s := int64(now().Sub(*t) / time.Second)
	return &s
}

func mb(kb *int64, roundUp bool) int64 {
	if kb == nil {
		return 0
	}
	if roundUp {
		return (*kb + 1023) / 1024
	}
	return *kb / 1024
}

// ───────── handlers ─────────

// backups answers the project's backup state from the store alone: nothing
// is asked of the host or the project.
func (a *api) backups(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	p, err := a.st.GetProject(ctx, ref)
	if err != nil {
		return nil, err
	}
	out := backupsJSON{Ref: ref, Layout: layoutOf(p.Config), Sets: []setJSON{}, InfoVersions: []infoVersionJSON{},
		Timelines: []timelineJSON{}, Gaps: []gapJSON{}, Notices: []noticeJSON{}, Restores: []restoreJSON{}}
	if out.Layout < 2 {
		return out, nil
	}
	ops, err := a.st.ListOperations(ctx, ref)
	if err != nil {
		return nil, err
	}
	// ponytail: restores among the ref's newest 200 operations (ListOperations' cap).
	for _, o := range ops {
		if o.Kind != "restore" || len(out.Restores) == maxRestores {
			continue
		}
		var params struct{ To, From string }
		var result struct {
			NewTimeline *int `json:"new_timeline"`
		}
		json.Unmarshal(o.Params, &params)
		json.Unmarshal(o.Result, &result)
		rs := restoreJSON{OperationID: o.ID, State: o.State, To: text(params.To), From: text(params.From),
			NewTimeline: result.NewTimeline}
		if slices.Contains([]string{"done", "failed", "aborted", "superseded"}, o.State) {
			rs.FinishedAt = optStamp(&o.UpdatedAt)
		}
		out.Restores = append(out.Restores, rs)
	}
	b, err := a.st.GetBackupState(ctx, ref)
	if errors.Is(err, store.ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	stanza, inc := ref+"-"+text(b.Incarnation), text(b.Incarnation)
	out.Stanza, out.Incarnation = &stanza, &inc

	sets, err := a.st.ListSets(ctx, ref) // oldest first
	if err != nil {
		return nil, err
	}
	if len(sets) > 0 {
		out.Window.Earliest = optStamp(&sets[0].StopAt)
	}
	out.Window.Latest = optStamp(b.LastPushOK)
	for _, s := range slices.Backward(sets) {
		if len(out.Sets) == maxSets {
			break
		}
		out.Sets = append(out.Sets, setJSON{Label: text(s.Label), Timeline: s.TLI, Start: stamp(s.StartAt), Stop: stamp(s.StopAt),
			StartSegment: text(s.StartSegment), StopSegment: text(s.StopSegment), Replicated: s.Replicated,
			ListedAt: optStamp(s.ListedAt)})
	}

	push := &pushJSON{LastOK: optStamp(b.LastPushOK), LagSeconds: lag(b.LastPushOK), SpoolEntries: b.SpoolEntries,
		SpoolBytes: b.SpoolBytes, SpoolOldest: optStamp(b.SpoolOldest)}
	if b.NewestSegment != "" {
		s := text(b.NewestSegment)
		push.NewestSegment = &s
	}
	out.Push = push
	if b.QuotaAt != nil {
		out.Quota = &quotaJSON{Taken: stamp(*b.QuotaAt), DiskUsedMB: mb(b.DiskUsedKB, true), DiskQuotaMB: mb(b.DiskHardKB, false),
			RepoUsedMB: mb(b.RepoUsedKB, true), RepoQuotaMB: mb(b.RepoHardKB, false)}
	}

	recorded, err := a.st.ObjectCount(ctx, ref)
	if err != nil {
		return nil, err
	}
	// The repository's quota is the disk quota in this release.
	bytesBudget, objectsBudget := bklimit.Budgets(p.Config.DiskQuotaMB, p.Config.UploadMBPerDay, p.Config.UploadObjectsPerDay)
	repl := &replicationJSON{Declared: a.offsite(), LastOK: optStamp(b.LastReplOK), LagSeconds: lag(b.LastReplOK),
		PausedUntil: optStamp(b.ReplPausedUntil), Rebuilding: b.RebuildPages > 0 || b.RebuildKeyMarker != "",
		BytesBudget: bytesBudget, ObjectsBudget: objectsBudget, ObjectsRecorded: recorded}
	// The counters are of their UTC day; another day's are not today's.
	if b.BudgetDay != nil && b.BudgetDay.UTC().Format(time.DateOnly) == now().UTC().Format(time.DateOnly) {
		repl.BytesToday, repl.ObjectsToday = b.BytesToday, b.ObjectsToday
	}
	out.Replication = repl

	infos, err := a.st.ListInfoVersions(ctx, ref, maxInfoVersions)
	if err != nil {
		return nil, err
	}
	for _, v := range infos {
		out.InfoVersions = append(out.InfoVersions, infoVersionJSON{Name: text(v.Name), VersionID: pgsock.Sanitize(v.VersionID, maxMessage),
			At: stamp(v.UploadedAt), SHA256: hex.EncodeToString(v.SHA256)})
	}
	tls, err := a.st.Timelines(ctx, ref)
	if err != nil {
		return nil, err
	}
	for _, tl := range tls {
		t := timelineJSON{Timeline: tl.TLI, State: tl.State}
		if tl.OpID != 0 {
			t.OperationID = &tl.OpID
		}
		out.Timelines = append(out.Timelines, t)
	}
	gaps, ats, err := a.st.ListGaps(ctx, ref)
	if err != nil {
		return nil, err
	}
	for i, g := range gaps[:min(len(gaps), maxGaps)] {
		out.Gaps = append(out.Gaps, gapJSON{Cause: text(g.Cause), FirstSegment: text(g.First), LastSegment: text(g.Last),
			At: stamp(ats[i]), Detail: text(g.Detail)})
	}
	notices, err := a.st.ListNotices(ctx, ref)
	if err != nil {
		return nil, err
	}
	for _, n := range notices[:min(len(notices), maxNotices)] {
		out.Notices = append(out.Notices, noticeJSON{Code: text(n.Code), Count: n.Count, FirstAt: stamp(n.FirstAt),
			LastAt: stamp(n.LastAt), Detail: text(n.Detail)})
	}
	return out, nil
}

// restoreTarget checks a restore's target: latest, an RFC 3339 time with its
// offset, or a WAL position with or without "lsn:" (returned with it).
func restoreTarget(s string) (string, bool) {
	switch {
	case len(s) > maxTarget:
		return "", false
	case s == "latest":
		return s, true
	case lsnRE.MatchString(s):
		return "lsn:" + strings.TrimPrefix(s, "lsn:"), true
	}
	_, err := time.Parse(time.RFC3339, s)
	return s, err == nil
}

// restore validates the request and hands it to Ops.Submit as
// {"to","timeline","from"}: timeline 0 and from "" when not given. Whether the
// target lies in the window, which set serves it and where it is read from
// are decided there, from the store's record.
func (a *api) restore(r *http.Request) (any, error) {
	ref, err := pathRef(r)
	if err != nil {
		return nil, err
	}
	var req struct {
		To       *string `json:"to"`
		Timeline *int64  `json:"timeline"`
		From     *string `json:"from"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.To == nil {
		return nil, badRequest("to is required: latest, a time or a WAL position")
	}
	to, ok := restoreTarget(*req.To)
	if !ok {
		return nil, badRequest("to must be latest (the end of the archive), an RFC 3339 time with its offset " +
			"(2026-11-18T10:43:32Z) or a WAL position (0/16B3748)")
	}
	params := struct {
		To       string `json:"to"`
		Timeline int64  `json:"timeline"`
		From     string `json:"from"`
	}{To: to}
	if req.Timeline != nil {
		if *req.Timeline < 1 || *req.Timeline > maxTimeline {
			return nil, badRequest("timeline must be 1 to %d; omit it for the newest recorded timeline", maxTimeline)
		}
		params.Timeline = *req.Timeline
	}
	if req.From != nil {
		if *req.From != "local" && *req.From != "offsite" {
			return nil, badRequest("from must be local or offsite; omit it for the default")
		}
		params.From = *req.From
	}
	b, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	id, err := a.ops.Submit(r.Context(), "restore", ref, b)
	if err != nil {
		return nil, err
	}
	return mutationJSON{ref, id}, nil
}

// cleanResult is an operation's stored result with every text and member
// name sanitised; null when there is none or it does not decode.
func cleanResult(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil
	}
	return cleanValue(v)
}

func cleanValue(v any) any {
	switch x := v.(type) {
	case string:
		return pgsock.Sanitize(x, maxMessage)
	case []any:
		for i := range x {
			x[i] = cleanValue(x[i])
		}
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[pgsock.Sanitize(k, maxName)] = cleanValue(e)
		}
		return m
	}
	return v
}
