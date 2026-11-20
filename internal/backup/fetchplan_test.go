package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/store"
)

const planSet = "20261118-104332F"

var listed = time.Unix(1_700_001_000, 0).UTC() // the set's listed_at

// planned sets up a restoring project whose record is rebuilt, with set
// planSet on timeline 1 from segment 4, listed at listed.
func (e *env) plannedProject() (ref, stanza string) {
	e.t.Helper()
	ref = e.project("restoring")
	e.rebuilt(ref)
	e.backupSetOf(ref, planSet, 1, "000000010000000000000004", &listed)
	return ref, ref + "-1"
}

func (e *env) timeline(ref string, tli int, state string) {
	e.t.Helper()
	_, err := e.db.Exec(context.Background(), "insert into backup_timeline (subject, tli, state, launch) values ($1, $2, $3, 0)", ref, tli, state)
	must(e.t, err)
}

func (e *env) infoVersion(ref, name, version string, h byte, at time.Time) {
	e.t.Helper()
	_, err := e.db.Exec(context.Background(), `insert into offsite_info_version (subject, name, version_id, sha256, uploaded_at)
		values ($1, $2, $3, $4, $5)`, ref, name, version, bytes.Repeat([]byte{h}, 32), at)
	must(e.t, err)
}

// planOf builds the plan of planSet (or set) to target to with extra.
func (e *env) planOf(ref, set, to string, extra int, gucs map[string]string) (plan, error) {
	e.t.Helper()
	s, err := e.r.subjectOf(context.Background(), ref)
	must(e.t, err)
	tg, err := parseTarget(to)
	must(e.t, err)
	return e.r.fetchPlan(context.Background(), s, gucs, fetchParams{Set: set, To: to, Extra: extra}, tg)
}

func (e *env) mustPlan(ref, to string, extra int, gucs map[string]string) plan {
	e.t.Helper()
	pl, err := e.planOf(ref, planSet, to, extra, gucs)
	must(e.t, err)
	return pl
}

func keysOf(pl plan) []string {
	var ks []string
	for _, r := range pl.rows {
		ks = append(ks, r.Key)
	}
	slices.Sort(ks)
	return ks
}

func has(pl plan, key string) bool { return slices.Contains(keysOf(pl), key) }

func h32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func codeOf(err error) string {
	var je *jobError
	if errors.As(err, &je) {
		return je.code
	}
	return ""
}

func TestPlan_SetByLabelFromRecord(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	later := listed.Add(100 * time.Second)
	e.backupSetOf(ref, "20261119-104332F", 1, "000000010000000000000009", &later)
	mine, theirs := setKey(st, planSet, "backup.manifest"), setKey(st, "20261119-104332F", "backup.manifest")
	e.object(ref, mine, 10, h32(1), "a", listed.Add(-10*time.Second))
	e.object(ref, setKey(st, planSet, "pg_data/base/1"), 10, h32(2), "b", listed.Add(time.Hour)) // its own set: whenever recorded
	e.object(ref, theirs, 10, h32(3), "c", listed.Add(500*time.Second))
	pl := e.mustPlan(ref, "latest", 0, nil)
	if !has(pl, mine) || !has(pl, setKey(st, planSet, "pg_data/base/1")) || has(pl, theirs) {
		t.Fatalf("plan of %s: %q", planSet, keysOf(pl))
	}
	pl2, err := e.planOf(ref, "20261119-104332F", "latest", 0, nil)
	must(t, err)
	if !has(pl2, theirs) || !has(pl2, mine) {
		t.Fatalf("plan of the later set: %q", keysOf(pl2))
	}
	// A label the record does not hold, and a set not listed off-site, are refused.
	e.backupSetOf(ref, "20261120-104332F", 1, "000000010000000000000009", nil)
	for _, l := range []string{"20261121-104332F", "20261120-104332F"} {
		if _, err := e.planOf(ref, l, "latest", 0, nil); err == nil {
			t.Fatalf("set %s planned", l)
		}
	}
}

func TestPlan_InfoAsOfListedAt(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	e.infoVersion(ref, "backup.info", "old", 1, listed.Add(-5*time.Second))
	e.infoVersion(ref, "backup.info", "older", 4, listed.Add(-50*time.Second))
	e.infoVersion(ref, "backup.info", "new", 2, listed.Add(5*time.Second))
	e.infoVersion(ref, "archive.info", "arch", 3, listed) // at listed_at: taken
	pl := e.mustPlan(ref, "latest", 0, nil)
	var got []string
	for _, r := range pl.rows {
		got = append(got, r.Key+"@"+r.VersionID+"#"+r.SHA256[:2])
	}
	slices.Sort(got)
	want := []string{"archive/" + st + "/archive.info@arch#03", "backup/" + st + "/backup.info@old#01"}
	if !slices.Equal(got, want) {
		t.Fatalf("plan %q, want %q", got, want)
	}
}

func TestPlan_OtherSetsListedThen(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	before, after := setKey(st, "20261117-104332F", "backup.manifest"), setKey(st, "20261117-104332F", "pg_data/base/2")
	e.object(ref, before, 1, h32(1), "a", listed)
	e.object(ref, after, 1, h32(2), "b", listed.Add(time.Second))
	hm := "backup/" + st + "/backup.history/2026/20261117-104332F.manifest.gz"
	e.object(ref, hm, 1, h32(3), "c", listed.Add(-time.Second))
	if pl := e.mustPlan(ref, "latest", 0, nil); !has(pl, before) || !has(pl, hm) || has(pl, after) {
		t.Fatalf("plan %q", keysOf(pl))
	}
}

func TestPlan_ArchiveFromSetStart(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	for n := uint32(2); n <= 5; n++ {
		e.object(ref, segKey(st, 1, n), 1, h32(byte(n)), "v", listed)
		e.object(ref, labelKey(st, 1, n), 1, h32(byte(n)), "v", listed)
	}
	pl := e.mustPlan(ref, "latest", 0, nil)
	want := []string{labelKey(st, 1, 4), labelKey(st, 1, 5), segKey(st, 1, 4), segKey(st, 1, 5)}
	slices.Sort(want)
	if got := keysOf(pl); !slices.Equal(got, want) {
		t.Fatalf("plan %q, want %q", got, want)
	}
}

func TestPlan_HoldsEveryAbandonedHistory_WithoutItTheNumberIsTakenAgain(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref, st := e.plannedProject()
	e.timeline(ref, 2, "abandoned")
	e.timeline(ref, 3, "pending")
	e.object(ref, histKey(st, 2), 1, h32(2), "h2", listed)
	pl := e.mustPlan(ref, "latest", 0, nil)
	if !slices.Equal(pl.histories, []string{"00000002.history"}) || !has(pl, histKey(st, 2)) {
		t.Fatalf("histories %q, plan %q", pl.histories, keysOf(pl))
	}
	held := func(hs []string) []int {
		var ts []int
		for _, h := range hs {
			var n int
			fmt.Sscanf(h, "%08X.history", &n)
			ts = append(ts, n)
		}
		return ts
	}
	var op int64
	must(t, e.db.QueryRow(ctx, `insert into operation (ref, kind, state, step, attempts, params, epoch, generation)
		values ($1, 'restore', 'running', 'T7', 1, '{}', 1, 1) returning id`, ref).Scan(&op))
	// Control: the plan without that one name would give timeline 2 again,
	// whose history the record already holds: the store refuses it.
	if _, err := e.st.BeginRecoveryAttempt(ctx, ref, st, op, held(nil)); !errors.Is(err, store.ErrTimelineConflict) {
		t.Fatalf("without the abandoned history: %v", err)
	}
	if n, err := e.st.BeginRecoveryAttempt(ctx, ref, st, op, held(pl.histories)); err != nil || n != 3 {
		t.Fatalf("next timeline %d (%v), want 3, the pending one", n, err)
	}
}

func TestPlan_TimeTargetMarginFromTheConstants(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	tt := listed.Add(time.Hour)
	at := map[uint32]time.Duration{4: -100 * time.Second, 5: 960 * time.Second, 6: 961 * time.Second, 7: 1920 * time.Second,
		8: 1921 * time.Second, 9: 1_000_000 * time.Second}
	for n, d := range at {
		e.object(ref, segKey(st, 1, n), 1, h32(byte(n)), "v", tt.Add(d))
	}
	segs := func(ns ...uint32) []string {
		var ks []string
		for _, n := range ns {
			ks = append(ks, segKey(st, 1, n))
		}
		return ks
	}
	to := tt.Format(time.RFC3339)
	g := map[string]string{"archive_timeout": "60"} // 60 + 300 + 600 = 960 s
	for _, c := range []struct {
		gucs  map[string]string
		extra int
		want  []string
	}{
		{g, 0, segs(4, 5, 6)},          // up to +960 s, and one segment more
		{g, 1, segs(4, 5, 6, 7, 8)},    // doubled: +1,920 s
		{g, 4, segs(4, 5, 6, 7, 8, 9)}, // above three doublings: the whole archive
		{nil, 0, segs(4, 5, 6, 7)},     // the default 300 s: +1,200 s
		{map[string]string{"archive_timeout": "1min"}, 0, segs(4, 5, 6)},
	} {
		if got := keysOf(e.mustPlan(ref, to, c.extra, c.gucs)); !slices.Equal(got, c.want) {
			t.Fatalf("%v extra %d: %q, want %q", c.gucs, c.extra, got, c.want)
		}
	}
	if m := bklimit.FetchMargin(60*time.Second, 0); m != 960*time.Second {
		t.Fatalf("margin %v", m)
	}
}

func TestPlan_LSNTarget(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	for n := uint32(4); n <= 7; n++ {
		e.object(ref, segKey(st, 1, n), 1, h32(byte(n)), "v", listed)
	}
	want := []string{segKey(st, 1, 4), segKey(st, 1, 5)}
	if got := keysOf(e.mustPlan(ref, "lsn:0/5000100", 0, nil)); !slices.Equal(got, want) {
		t.Fatalf("plan %q, want %q", got, want)
	}
	if got := keysOf(e.mustPlan(ref, "lsn:0/5FFFFFF", 0, nil)); !slices.Equal(got, want) {
		t.Fatalf("plan at the segment's end %q", got)
	}
	for _, bad := range []string{"lsn:0/", "lsn:x/1", "lsn:123456789/0", "yesterday"} {
		if _, err := parseTarget(bad); err == nil {
			t.Fatalf("target %q accepted", bad)
		}
	}
}

func TestPlan_OnlyAdmittedTimelines(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	e.object(ref, segKey(st, 1, 5), 1, h32(1), "v", listed)
	e.object(ref, segKey(st, 2, 5), 1, h32(2), "v", listed)
	e.object(ref, histKey(st, 2), 1, h32(3), "v", listed)
	e.object(ref, labelKey(st, 2, 5), 1, h32(4), "v", listed)
	pl := e.mustPlan(ref, "latest", 0, nil)
	if got := keysOf(pl); !slices.Equal(got, []string{segKey(st, 1, 5)}) || len(pl.histories) != 0 {
		t.Fatalf("plan %q, histories %q", got, pl.histories)
	}
	e.timeline(ref, 2, "abandoned") // control: admitted
	if got := keysOf(e.mustPlan(ref, "latest", 0, nil)); len(got) != 4 {
		t.Fatalf("plan with timeline 2 admitted %q", got)
	}
}

func TestPlan_VersionIDOrOldest(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	e.object(ref, segKey(st, 1, 4), 1, h32(1), "recorded", listed)   // copied: version and hash
	e.object(ref, segKey(st, 1, 5), 2, nil, "oldest-listed", listed) // rebuilt: version, no hash
	e.object(ref, segKey(st, 1, 6), 3, nil, "", listed)              // listed without a version id
	pl := e.mustPlan(ref, "latest", 0, nil)
	var buf bytes.Buffer
	must(t, jobio.WritePlan(&buf, pl.rows))
	want := segKey(st, 1, 4) + "\trecorded\t" + hex.EncodeToString(h32(1)) + "\t1\n" +
		segKey(st, 1, 5) + "\toldest-listed\t-\t2\n" +
		segKey(st, 1, 6) + "\t-\t-\t3\n"
	if buf.String() != want {
		t.Fatalf("plan\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestPlan_NeverPlansUnrecordedKey(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	e.timeline(ref, 2, "abandoned") // admitted, its history not in the record
	recorded := segKey(st, 1, 4)
	e.object(ref, recorded, 1, h32(1), "v", listed)
	e.object(ref, segKey(ref+"-2", 1, 4), 1, h32(2), "v", listed)          // another stanza
	e.object(ref, "archive/"+st+"/16-1/notes.txt", 1, h32(3), "v", listed) // no repository path
	e.object(ref, "archive/"+st+"/archive.info", 1, nil, "v", listed)      // an info file is planned from its versions only
	pl := e.mustPlan(ref, "latest", 0, nil)
	if got := keysOf(pl); !slices.Equal(got, []string{recorded}) || len(pl.histories) != 0 {
		t.Fatalf("plan %q, histories %q", got, pl.histories)
	}
}

func TestPlan_InfoVersionsByTheRecordsOwnTimes_NeverTheStoresClock(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	// A rebuilt row of the info file carries the object store's time.
	e.object(ref, "backup/"+st+"/backup.info", 1, nil, "store-listed", listed.Add(-time.Hour))
	e.infoVersion(ref, "backup.info", "recorded", 1, listed.Add(-time.Second))
	e.infoVersion(ref, "backup.info", "after", 2, listed.Add(time.Second))
	pl := e.mustPlan(ref, "latest", 0, nil)
	if len(pl.rows) != 1 || pl.rows[0].VersionID != "recorded" || pl.rows[0].Key != "backup/"+st+"/backup.info" {
		t.Fatalf("plan %+v", pl.rows)
	}
}

// ───────── through the runner ─────────

const fetchParamsJSON = `{"set":"` + planSet + `","to":"latest","timeline":0,"extra":0}`

func (e *env) fetch(ref, params string) jobRow {
	e.t.Helper()
	op, id := e.parked(ref, "fetch", params)
	if !e.turn("backup") {
		e.t.Fatal("no fetch job picked")
	}
	_, err := e.db.Exec(context.Background(), "update operation set state = 'done' where id = $1", op)
	must(e.t, err)
	return e.job(id)
}

func TestPlan_RefusedUntilTheRecordIsRebuilt(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref, st := e.plannedProject()
	e.object(ref, segKey(st, 1, 4), 1, h32(1), "v", listed)
	_, err := e.db.Exec(context.Background(), "update backup_state set rebuild_epoch = 0 where subject = $1", ref)
	must(t, err)
	if got := e.fetch(ref, fetchParamsJSON); got.Code != "record_not_rebuilt" || len(e.ag.specs) != 0 {
		t.Fatalf("job %+v, launches %d", got, len(e.ag.specs))
	}
	e.rebuilt(ref)
	if got := e.fetch(ref, fetchParamsJSON); got.State != "done" || len(e.ag.specs) != 1 {
		t.Fatalf("rebuilt: job %+v, launches %d", got, len(e.ag.specs))
	}
}

func TestPlan_RefusesAboveRepoQuota(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref, st := e.plannedProject()
	e.object(ref, setKey(st, planSet, "pg_data/base/1"), 8192<<20, h32(1), "v", listed)
	e.object(ref, segKey(st, 1, 4), 1, h32(2), "v", listed)
	got := e.fetch(ref, fetchParamsJSON)
	ns, err := e.st.ListNotices(context.Background(), ref)
	must(t, err)
	if got.Code != "fetch_too_large" || len(e.ag.specs) != 0 || len(ns) != 1 || ns[0].Code != "fetch-too-large" {
		t.Fatalf("job %+v, launches %d, notices %+v", got, len(e.ag.specs), ns)
	}
	if slices.Contains(e.ag.called(), "SetReplicatorQuota 16384") {
		t.Fatal("the replicator's quota was set for a refused plan")
	}
	// Control: the same plan without its last byte fits.
	_, err = e.db.Exec(context.Background(), "update offsite_object set size = size - 1 where subject = $1 and size > 1", ref)
	must(t, err)
	if got := e.fetch(ref, fetchParamsJSON); got.State != "done" || len(e.ag.specs) != 1 {
		t.Fatalf("at the quota: job %+v, launches %d", got, len(e.ag.specs))
	}
}

func TestFetchLaunch_SetsReplicatorQuotaFirst_MaxBytesIsTheRepoQuota(t *testing.T) {
	e := newEnv(t)
	e.declare()
	big := e.project("active")
	_, err := e.db.Exec(context.Background(), `update project set config = jsonb_set(config, '{disk_quota_mb}', '16384') where ref = $1`, big)
	must(t, err)
	ref, st := e.plannedProject()
	e.object(ref, segKey(st, 1, 4), 5, h32(1), "v", listed)
	if got := e.fetch(ref, fetchParamsJSON); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	calls := e.ag.called()
	q, run := slices.Index(calls, "SetReplicatorQuota 32768"), slices.Index(calls, "RunJob "+ref+" fetch")
	if q < 0 || run < 0 || q > run {
		t.Fatalf("calls %q", calls)
	}
	s := e.ag.specs[0]
	in, err := jobio.ParseInput(s.Input)
	must(t, err)
	var rows []jobio.PlanRow
	must(t, jobio.ReadPlan(bytes.NewReader(s.Files["plan"]), func(r jobio.PlanRow) error { rows = append(rows, r); return nil }))
	if in.MaxBytes != 8192<<20 || in.Repl != nil || in.ListCurrent || len(rows) != 1 || rows[0].Key != segKey(st, 1, 4) ||
		string(s.Cred) != "PR\npr-secret" {
		t.Fatalf("input %+v, plan %+v", in, rows)
	}
}

func TestFetchRecord_HistoriesComeFromThePlan(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref, st := e.plannedProject()
	e.timeline(ref, 2, "abandoned")
	e.object(ref, histKey(st, 2), 1, h32(1), "v", listed)
	e.object(ref, segKey(st, 1, 4), 1, h32(2), "v", listed)
	got := e.fetch(ref, fetchParamsJSON)
	var doc struct {
		Files     int      `json:"files"`
		Histories []string `json:"histories"`
	}
	err := json.Unmarshal(got.Result, &doc)
	if got.State != "done" || err != nil || doc.Files != 1 || !slices.Equal(doc.Histories, []string{"00000002.history"}) {
		t.Fatalf("job %+v %s", got, got.Result)
	}
	// A job that names histories itself is refused whole.
	e.ag.setScript("fetch", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{Result: []byte(`{"ok":true,"files":1,"bytes":1,"histories":["00000005.history"]}` + "\n")}, nil
	})
	if got := e.fetch(ref, fetchParamsJSON); got.Code != "crashed" {
		t.Fatalf("job %+v", got)
	}
	// So is one that reports more than its plan or a control plane's figures.
	for _, res := range []jobio.FetchResult{{OK: true, Files: 3, Bytes: 1}, {OK: true, Files: 1, Bytes: 1, NewestSet: planSet}} {
		e.ag.setScript("fetch", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{Result: line(res)}, nil
		})
		if got := e.fetch(ref, fetchParamsJSON); got.Code != "crashed" {
			t.Fatalf("%+v: job %+v", res, got)
		}
	}
}

func TestFetch_ParamsDecodedStrictly(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref, st := e.plannedProject()
	e.object(ref, segKey(st, 1, 4), 1, h32(1), "v", listed)
	for _, p := range []string{`{}`, `{"set":"` + planSet + `","to":"latest","timeline":0,"extra":0,"more":1}`,
		`{"set":"x","to":"latest","timeline":0,"extra":0}`, `{"set":"` + planSet + `","to":"soon","timeline":0,"extra":0}`,
		`{"set":"` + planSet + `","to":"latest","timeline":0,"extra":-1}`, strings.Replace(fetchParamsJSON, `"to"`, `"To"`, 1)} {
		if got := e.fetch(ref, p); got.Code != "internal" {
			t.Fatalf("params %s: job %+v", p, got)
		}
	}
	if len(e.ag.specs) != 0 {
		t.Fatalf("launched %d", len(e.ag.specs))
	}
	if got := e.fetch(ref, fetchParamsJSON); got.State != "done" {
		t.Fatalf("control: %+v", got)
	}
}

// The control plane is fetched by recover alone, never through the runner.
func TestFetch_ControlPlaneRefused(t *testing.T) {
	e := newEnv(t)
	e.declare()
	e.controlPlane()
	e.rebuilt("cp")
	s, err := e.r.subjectOf(context.Background(), "cp")
	must(t, err)
	_, err = e.r.jobSpec(context.Background(), store.Job{ID: 1, Subject: "cp", Kind: "fetch", Params: []byte(fetchParamsJSON), DeadlineS: 1}, s)
	if codeOf(err) != "internal" || len(e.ag.called()) != 0 {
		t.Fatalf("cp fetch: %v, calls %q", err, e.ag.called())
	}
}

func TestPlan_ArchiveTimeoutDefaultAndFallback(t *testing.T) {
	for v, want := range map[string]time.Duration{"": 300 * time.Second, "45": 45 * time.Second, "45s": 45 * time.Second,
		"2min": 120 * time.Second, "soon": 3600 * time.Second, "-5": 3600 * time.Second, "99999": 3600 * time.Second} {
		g := map[string]string{"archive_timeout": v}
		if v == "" {
			g = nil
		}
		if got := archiveTimeout(g); got != want {
			t.Fatalf("%q: %v, want %v", v, got, want)
		}
	}
}

// The one segment more past a time cut is a segment, never a label file.
func TestPlan_OneMoreIsASegment(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	tt := listed.Add(time.Hour)
	e.object(ref, segKey(st, 1, 4), 1, h32(1), "v", tt)
	e.object(ref, labelKey(st, 1, 5), 1, h32(2), "v", tt.Add(2000*time.Second))
	e.object(ref, segKey(st, 1, 6), 1, h32(3), "v", tt.Add(2000*time.Second))
	want := []string{segKey(st, 1, 4), segKey(st, 1, 6)}
	if got := keysOf(e.mustPlan(ref, tt.Format(time.RFC3339), 0, nil)); !slices.Equal(got, want) {
		t.Fatalf("plan %q, want %q", got, want)
	}
}

// An info file is planned at its kind's bound, which counts against the quota.
func TestPlan_InfoRowsCountTheirBound(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	e.infoVersion(ref, "backup.info", "v", 1, listed)
	e.object(ref, setKey(st, planSet, "pg_data/base/1"), 8192<<20-bklimit.SmallMax+1, h32(2), "v", listed)
	_, err := e.planOf(ref, planSet, "latest", 0, nil)
	if codeOf(err) != "fetch_too_large" {
		t.Fatalf("plan over the quota by its info file: %v", err)
	}
	_, err = e.db.Exec(context.Background(), "update offsite_object set size = size - 1 where subject = $1", ref)
	must(t, err)
	pl, err := e.planOf(ref, planSet, "latest", 0, nil)
	must(t, err)
	if i := slices.IndexFunc(pl.rows, func(r jobio.PlanRow) bool { return strings.HasSuffix(r.Key, "backup.info") }); i < 0 || pl.rows[i].Size != bklimit.SmallMax {
		t.Fatalf("plan %+v", pl.rows)
	}
}

// The plan's histories are names, once each, in order, whatever the archive
// directories that hold them.
func TestPlan_HistoriesSortedAndOnce(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	e.timeline(ref, 2, "abandoned")
	e.timeline(ref, 3, "abandoned")
	e.object(ref, "archive/"+st+"/16-1/00000003.history", 1, h32(1), "v", listed)
	e.object(ref, "archive/"+st+"/17-1/00000002.history", 1, h32(2), "v", listed)
	e.object(ref, "archive/"+st+"/17-1/00000003.history", 1, h32(3), "v", listed)
	if pl := e.mustPlan(ref, "latest", 0, nil); !slices.Equal(pl.histories, []string{"00000002.history", "00000003.history"}) {
		t.Fatalf("histories %q", pl.histories)
	}
}

// A fetch that reports more bytes than its limit is crashed.
func TestFetchRecord_BytesBoundedByTheLimit(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref, st := e.plannedProject()
	e.object(ref, segKey(st, 1, 4), 1, h32(1), "v", listed)
	for b, want := range map[int64]string{8192<<20 + 1: "failed", 8192 << 20: "done"} {
		e.ag.setScript("fetch", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
			return agent.JobResult{Result: line(jobio.FetchResult{OK: true, Files: 1, Bytes: b})}, nil
		})
		if got := e.fetch(ref, fetchParamsJSON); got.State != want || want == "failed" && got.Code != "crashed" {
			t.Fatalf("%d bytes: job %+v", b, got)
		}
	}
}
