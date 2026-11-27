package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/walname"
)

const day = 24 * time.Hour

// opsJob inserts a job of subject as the queue leaves one; launch 0 is no
// number, a zero finished time none.
func opsJob(t *testing.T, s *Store, subject, kind, state string, launch int64, finished time.Time, result string) int64 {
	t.Helper()
	lane := "backup"
	if kind == "push" || kind == "replicate" {
		lane = "push"
	}
	var l *int64
	if launch != 0 {
		l = &launch
	}
	var fin, started *time.Time
	if !finished.IsZero() {
		fin = &finished
		st := finished.Add(-time.Minute)
		started = &st
	}
	var res *string
	if result != "" {
		res = &result
	}
	var id int64
	must(t, s.pool.QueryRow(context.Background(), `insert into backup_job (subject, lane, kind, state, deadline_s, launch,
		started_at, finished_at, result, created_at) values ($1, $2, $3, $4, 60, $5, $6, $7, $8::jsonb, coalesce($6, now()) - interval '1 minute') returning id`,
		subject, lane, kind, state, l, started, fin, res).Scan(&id))
	return id
}

const copyDone = `{"ok":true,"mode":"copy","complete":true}`

// --- same-location expire ---

func TestExpireAllowed_Table(t *testing.T) {
	ago := func(s *Store) time.Time { return memberDBNow(t, s).Add(-time.Hour) }
	for _, tc := range []struct {
		name  string
		setup func(s *Store, r string) (expire int64)
		want  bool
	}{
		{"push launched after the last complete copy", func(s *Store, r string) int64 {
			opsJob(t, s, r, "replicate", "done", 10, ago(s), copyDone)
			opsJob(t, s, r, "push", "done", 11, ago(s), `{}`)
			return opsJob(t, s, r, "expire", "running", 12, time.Time{}, "")
		}, false},
		{"an incomplete copy", func(s *Store, r string) int64 {
			opsJob(t, s, r, "push", "done", 10, ago(s), `{}`)
			opsJob(t, s, r, "replicate", "done", 11, ago(s), `{"mode":"copy","complete":false}`)
			return opsJob(t, s, r, "expire", "running", 12, time.Time{}, "")
		}, false},
		{"a rebuild page", func(s *Store, r string) int64 {
			opsJob(t, s, r, "push", "done", 10, ago(s), `{}`)
			opsJob(t, s, r, "replicate", "done", 11, ago(s), `{"mode":"rebuild","complete":true}`)
			return opsJob(t, s, r, "expire", "running", 12, time.Time{}, "")
		}, false},
		{"the copy launched last", func(s *Store, r string) int64 {
			opsJob(t, s, r, "push", "failed", 10, ago(s), `{}`)
			opsJob(t, s, r, "backup", "done", 11, ago(s), `{}`)
			opsJob(t, s, r, "expire", "done", 12, ago(s), `{}`)
			opsJob(t, s, r, "push", "queued", 0, time.Time{}, "")
			opsJob(t, s, r, "replicate", "done", 13, ago(s), copyDone)
			return opsJob(t, s, r, "expire", "running", 14, time.Time{}, "")
		}, true},
		{"a writer with a lower id launched after the copy", func(s *Store, r string) int64 {
			w := opsJob(t, s, r, "check", "queued", 0, time.Time{}, "")
			opsJob(t, s, r, "replicate", "done", 10, ago(s), copyDone)
			sqlExec(t, s, "update backup_job set state = 'failed', launch = 11, finished_at = now() where id = $1", w)
			return opsJob(t, s, r, "expire", "running", 12, time.Time{}, "")
		}, false},
		{"the expire being launched is no writer", func(s *Store, r string) int64 {
			opsJob(t, s, r, "seed", "done", 9, ago(s), `{}`)
			opsJob(t, s, r, "replicate", "done", 10, ago(s), copyDone)
			return opsJob(t, s, r, "expire", "running", 99, time.Time{}, "")
		}, true},
		{"the epoch not rebuilt", func(s *Store, r string) int64 {
			opsJob(t, s, r, "replicate", "done", 10, ago(s), copyDone)
			sqlExec(t, s, "update backup_state set rebuild_epoch = 0 where subject = $1", r)
			return opsJob(t, s, r, "expire", "running", 12, time.Time{}, "")
		}, false},
		{"no complete copy row left", func(s *Store, r string) int64 {
			opsJob(t, s, r, "stanza-create", "done", 9, ago(s), `{}`)
			return opsJob(t, s, r, "expire", "running", 12, time.Time{}, "")
		}, false},
		{"a complete copy that raised notices", func(s *Store, r string) int64 {
			opsJob(t, s, r, "push", "done", 9, ago(s), `{}`)
			opsJob(t, s, r, "replicate", "done", 10, ago(s), `{"mode":"copy","complete":true,"notices":[{"code":"offsite-differs"},{"code":"history-rewritten"},{"code":"unreadable-entry"}]}`)
			for _, c := range []string{"offsite-differs", "history-rewritten", "unreadable-entry"} {
				must(t, s.Notice(context.Background(), r, c, ""))
			}
			return opsJob(t, s, r, "expire", "running", 12, time.Time{}, "")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t, testConfig())
			r, _ := bsProject(t, s, 1)
			sqlExec(t, s, "update backup_state set rebuild_epoch = 1 where subject = $1", r)
			id := tc.setup(s, r)
			got, err := s.ExpireAllowed(context.Background(), r, id)
			must(t, err)
			if got != tc.want {
				t.Fatalf("ExpireAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMarkExpiredLocal_OnlyAbsentLabels(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	f := newPlanFix(t, s)
	early := memberDBNow(t, s).Add(-5 * day).Truncate(time.Microsecond)
	sqlExec(t, s, "update backup_set set expired_local_at = null")
	sqlExec(t, s, "update backup_set set expired_local_at = $2 where label = $1", f.labels[0], early)
	at := memberDBNow(t, s).Truncate(time.Microsecond)
	must(t, s.MarkExpiredLocal(ctx, f.r, f.labels[2:], at))
	for i, l := range f.labels {
		var got *time.Time
		must(t, s.pool.QueryRow(ctx, "select expired_local_at from backup_set where subject = $1 and label = $2", f.r, l).Scan(&got))
		switch i {
		case 0:
			timeIs(t, "an earlier mark", got, early)
		case 1:
			timeIs(t, "the absent label", got, at)
		default:
			if got != nil {
				t.Fatalf("listed label %s marked", l)
			}
		}
	}
	wantErr(t, s.MarkExpiredLocal(ctx, f.r, []string{"not a label"}, at), ErrConflict)
}

// --- the off-site plan ---

// planFix: ten daily sets whose jobs finished 10.5 … 1.5 days ago, the last
// two still at the same location, each set's rows recorded by the copy that
// followed its backup. Set i's backup job is launched at 100i+10, its copy at
// 100i+50.
type planFix struct {
	s         *Store
	r, stanza string
	now       time.Time
	labels    []string
	setKeys   [][]string // per set: the five kinds' keys, recorded by its copy
	otherKeys []string   // label, history and info keys, recorded at the lowest numbers
}

func bLaunch(i int) int64 { return int64(100*i + 10) }
func cLaunch(i int) int64 { return int64(100*i + 50) }

func newPlanFix(t *testing.T, s *Store) *planFix {
	t.Helper()
	f := &planFix{s: s, now: memberDBNow(t, s)}
	f.r, f.stanza = bsProject(t, s, 1)
	sqlExec(t, s, "update backup_state set rebuild_epoch = 1 where subject = $1", f.r)
	for i := 0; i < 10; i++ {
		fin := f.now.Add(-time.Duration((10.5 - float64(i)) * float64(day)))
		label := fmt.Sprintf("202611%02d-120000F", i+1)
		f.labels = append(f.labels, label)
		bj := opsJob(t, s, f.r, "backup", "done", bLaunch(i), fin, `{}`)
		opsJob(t, s, f.r, "replicate", "done", cLaunch(i), fin.Add(time.Hour), copyDone)
		var local *time.Time
		if i < 8 {
			l := fin.Add(2 * day)
			local = &l
		}
		sqlExec(t, s, `insert into backup_set (subject, label, tli, start_segment, stop_segment, start_lsn, stop_lsn, start_at, stop_at,
			job_id, replicated, listed_at, expired_local_at) values ($1, $2, 1, $3, $3, '0/1', '0/2', $4, $4, $5, true, $6, $7)`,
			f.r, label, bsSeg(1, i), fin, bj, fin.Add(time.Hour), local)
		seg := bsSeg(1, 100+i)
		keys := []string{
			"backup/" + f.stanza + "/" + label + "/backup.manifest",
			"backup/" + f.stanza + "/" + label + "/backup.manifest.copy",
			"backup/" + f.stanza + "/" + label + "/pg_data/base/1/1259",
			"backup/" + f.stanza + "/backup.history/2026/" + label + ".manifest.gz",
			bsSegKey(f.stanza, "17-1", seg),
		}
		f.setKeys = append(f.setKeys, keys)
		for _, k := range keys {
			planRow(t, s, f.r, k, cLaunch(i), fin.Add(time.Hour))
		}
	}
	f.otherKeys = []string{
		"archive/" + f.stanza + "/17-1/" + bsSeg(1, 100)[:16] + "/" + bsSeg(1, 100) + ".00000028.backup",
		bsHistKey(f.stanza, "17-1", 2),
		"archive/" + f.stanza + "/archive.info",
		"backup/" + f.stanza + "/backup.info",
	}
	for _, k := range f.otherKeys {
		planRow(t, s, f.r, k, 1, f.now.Add(-20*day))
	}
	return f
}

func planRow(t *testing.T, s *Store, subject, key string, launch int64, at time.Time) {
	t.Helper()
	sqlExec(t, s, `insert into offsite_object (subject, key, size, version_id, uploaded_at, launch) values ($1, $2, 1, 'v', $3, $4)`,
		subject, key, at, launch)
}

// keysOf is the planned keys of sets, in plan order: launch, then key.
func (f *planFix) keysOf(sets ...int) []string {
	var out []string
	for _, i := range sets {
		k := slices.Clone(f.setKeys[i])
		slices.Sort(k)
		out = append(out, k...)
	}
	return out
}

func (f *planFix) plan(t *testing.T, now time.Time, window time.Duration, minNewer, max int) ExpirePlan {
	t.Helper()
	p, err := f.s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, window, 72*time.Hour, now, minNewer, max)
	must(t, err)
	return p
}

func wantPlan(t *testing.T, got ExpirePlan, keys []string, anchor string, keep int64) {
	t.Helper()
	if !slices.Equal(got.Keys, keys) || got.Anchor != anchor || got.KeepLaunch != keep {
		t.Fatalf("plan: anchor %q keep %d keys %v\nwant anchor %q keep %d keys %v", got.Anchor, got.KeepLaunch, got.Keys, anchor, keep, keys)
	}
}

func TestOffsiteExpirePlan_KeepsTheWindowAndEveryHistory(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	p := f.plan(t, f.now, 7*day, 6, 2000)
	wantPlan(t, p, f.keysOf(0, 1, 2), f.labels[3], bLaunch(3))
	if p.More || p.HeldByLocal != 0 {
		t.Fatalf("more %v, held by local %d", p.More, p.HeldByLocal)
	}
	for _, k := range p.Keys {
		if kind, _, _, _ := walname.RepoPath(f.stanza, k); kind == walname.History || kind == walname.Info || kind == walname.Label {
			t.Fatalf("planned %s", k)
		}
	}
}

func TestOffsiteExpirePlan_CutIsByLaunchNotByTime(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	want := f.plan(t, f.now, 7*day, 6, 2000)
	for _, at := range []time.Time{f.now.Add(-3 * day), f.now.Add(4 * day), f.now.Add(-30 * day)} {
		sqlExec(t, s, "update offsite_object set uploaded_at = $1", at)
		wantPlan(t, f.plan(t, f.now, 7*day, 6, 2000), want.Keys, want.Anchor, want.KeepLaunch)
	}
}

func TestOffsiteExpirePlan_BackwardStepDuringUploadsKeepsTheSetsWAL(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	// The anchor's own first segments carry upload times before its job started.
	sqlExec(t, s, "update offsite_object set uploaded_at = now() - interval '30 days' where key = any($1)", f.setKeys[3])
	sqlExec(t, s, "update backup_job set started_at = now() - interval '1 minute' where subject = $1 and launch = $2", f.r, bLaunch(3))
	p := f.plan(t, f.now, 7*day, 6, 2000)
	for _, k := range f.setKeys[3] {
		if slices.Contains(p.Keys, k) {
			t.Fatalf("the anchor's key %s planned", k)
		}
	}
	wantPlan(t, p, f.keysOf(0, 1, 2), f.labels[3], bLaunch(3))
}

func TestOffsiteExpirePlan_ClockAheadKeepsSevenSets(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	ahead := f.now.Add(365 * day)
	wantPlan(t, f.plan(t, ahead, 7*day, 6, 2000), f.keysOf(0, 1, 2), f.labels[3], bLaunch(3))
	sqlExec(t, s, "update backup_set set replicated = false where label = any($1)", f.labels[7:])
	wantPlan(t, f.plan(t, ahead, 7*day, 6, 2000), nil, f.labels[0], bLaunch(0))
}

func TestOffsiteExpirePlan_ForgedReportedFieldsChangeNothing(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	want := f.plan(t, f.now, 7*day, 6, 2000)
	sqlExec(t, s, `update backup_set set stop_at = stop_at - interval '8 days', start_at = start_at - interval '8 days',
		start_segment = '00000001FFFFFFFF000000FF', stop_segment = '00000001FFFFFFFF000000FF', start_lsn = 'FF/0', stop_lsn = 'FF/1'`)
	swap := func(a, b string) {
		sqlExec(t, s, "update backup_set set label = '19990101-000000F' where label = $1", a)
		sqlExec(t, s, "update backup_set set label = $1 where label = $2", a, b)
		sqlExec(t, s, "update backup_set set label = $1 where label = '19990101-000000F'", b)
	}
	swap(f.labels[0], f.labels[1])
	swap(f.labels[4], f.labels[8])
	sqlExec(t, s, "update backup_state set newest_segment = '00000001FFFFFFFF000000FF'")
	got := f.plan(t, f.now, 7*day, 6, 2000)
	if !slices.Equal(got.Keys, want.Keys) || got.KeepLaunch != want.KeepLaunch {
		t.Fatalf("forged rows changed the plan:\n%v\n%v", got.Keys, want.Keys)
	}
}

func TestOffsiteExpirePlan_AnchorIsReplicated(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	sqlExec(t, s, "update backup_set set replicated = false where label = $1", f.labels[3])
	wantPlan(t, f.plan(t, f.now, 7*day, 6, 2000), f.keysOf(0, 1), f.labels[2], bLaunch(2))
	// A set whose job did not end done is no anchor either.
	sqlExec(t, s, "update backup_set set replicated = true where label = $1", f.labels[3])
	sqlExec(t, s, "update backup_job set state = 'failed' where subject = $1 and launch = $2", f.r, bLaunch(3))
	wantPlan(t, f.plan(t, f.now, 7*day, 6, 2000), f.keysOf(0, 1), f.labels[2], bLaunch(2))
}

func TestOffsiteExpirePlan_NeverAheadOfTheSameLocation(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	sqlExec(t, s, "update backup_set set expired_local_at = null where label = $1", f.labels[0])
	p := f.plan(t, f.now, 7*day, 6, 2000)
	wantPlan(t, p, nil, f.labels[3], bLaunch(0))
	if p.HeldByLocal != 1 {
		t.Fatalf("held by local %d", p.HeldByLocal)
	}
	// Control: held for less than the limit, it is not counted.
	p, err := s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, 7*day, 4*day, f.now, 6, 2000)
	must(t, err)
	if p.HeldByLocal != 0 {
		t.Fatalf("held by local %d under a longer limit", p.HeldByLocal)
	}
}

func TestOffsiteExpirePlan_RestoreBaseStaysUntilTheAnchorPostdatesTheRestore(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	op := bsOp(t, s, f.r)
	sqlExec(t, s, `update operation set params = jsonb_build_object('set', $2::text) where id = $1`, op, f.labels[0])
	sqlExec(t, s, "insert into backup_timeline (subject, tli, state, op_id, launch) values ($1, 2, 'recorded', $2, $3)", f.r, op, bLaunch(3)+5)
	// The timeline was recorded after the anchor's job: the base stays with all
	// recorded since its job.
	wantPlan(t, f.plan(t, f.now, 7*day, 6, 2000), nil, f.labels[3], bLaunch(0))
	// With an anchor launched after that number the base goes.
	wantPlan(t, f.plan(t, f.now.Add(day), 7*day, 5, 2000), f.keysOf(0, 1, 2, 3), f.labels[4], bLaunch(4))
	// A restore whose timeline is not recorded keeps nothing.
	sqlExec(t, s, "update backup_timeline set state = 'pending' where subject = $1 and tli = 2", f.r)
	wantPlan(t, f.plan(t, f.now, 7*day, 6, 2000), f.keysOf(0, 1, 2), f.labels[3], bLaunch(3))
}

func TestOffsiteExpirePlan_NothingWhileAStayingSetsJobHasNoNumber(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	sqlExec(t, s, "update backup_job set launch = null where subject = $1 and launch = $2", f.r, bLaunch(9))
	p := f.plan(t, f.now, 7*day, 6, 2000)
	if len(p.Keys) != 0 || p.Anchor == "" {
		t.Fatalf("plan %+v", p)
	}
}

func TestOffsiteExpirePlan_RowsFromBeforeTheMigrationGoFirst(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	old := []string{bsSegKey(f.stanza, "17-1", bsSeg(1, 1)), bsSegKey(f.stanza, "17-1", bsSeg(1, 2))}
	for _, k := range old {
		planRow(t, s, f.r, k, 0, f.now)
	}
	p := f.plan(t, f.now, 7*day, 6, 3)
	if !slices.Equal(p.Keys[:2], old) || !p.More || len(p.Keys) != 3 {
		t.Fatalf("plan %+v", p)
	}
}

func TestOffsiteExpirePlan_UnrecordedKeyIsNeverPlanned(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	gone := f.setKeys[0][2]
	sqlExec(t, s, "delete from offsite_object where key = $1", gone)
	p := f.plan(t, f.now, 7*day, 6, 2000)
	if slices.Contains(p.Keys, gone) || len(p.Keys) != 14 {
		t.Fatalf("plan %+v", p)
	}
	for _, k := range p.Keys {
		if _, _, ok := bsObject(t, s, f.r, k); !ok {
			t.Fatalf("planned %s, which the record does not hold", k)
		}
	}
}

func TestOffsiteExpirePlan_NotRebuilt(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	sqlExec(t, s, "update backup_state set rebuild_epoch = 0")
	p, err := s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, 7*day, 72*time.Hour, f.now, 6, 2000)
	wantErr(t, err, ErrNotRebuilt)
	if len(p.Keys) != 0 || p.Anchor != "" {
		t.Fatalf("plan %+v", p)
	}
	// Another stanza is refused.
	_, err = s.OffsiteExpirePlan(context.Background(), f.r, f.r+"-2", 7*day, 72*time.Hour, f.now, 6, 2000)
	if err == nil || errors.Is(err, ErrNotRebuilt) {
		t.Fatalf("another stanza: %v", err)
	}
}

func TestOffsiteExpirePlan_AJobTimeInTheFutureIsErrClock(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	j := opsJob(t, s, f.r, "check", "done", 2000, f.now.Add(time.Hour), `{}`)
	_, err := s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, 7*day, 72*time.Hour, f.now, 6, 2000)
	wantErr(t, err, ErrClock)
	// Control: dated a minute before now.
	sqlExec(t, s, "update backup_job set started_at = $2, finished_at = $2, created_at = $2 where id = $1", j, f.now.Add(-time.Minute))
	f.plan(t, f.now, 7*day, 6, 2000)
	sqlExec(t, s, "update backup_job set created_at = $2 where id = $1", j, f.now.Add(time.Hour))
	_, err = s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, 7*day, 72*time.Hour, f.now, 6, 2000)
	wantErr(t, err, ErrClock)
}

func TestOffsiteExpirePlan_CapLowestNumbersFirstAndMore(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	all := f.keysOf(0, 1, 2)
	p := f.plan(t, f.now, 7*day, 6, 6)
	if !slices.Equal(p.Keys, all[:6]) || !p.More {
		t.Fatalf("capped plan %+v", p)
	}
	if p = f.plan(t, f.now, 7*day, 6, len(all)); !slices.Equal(p.Keys, all) || p.More {
		t.Fatalf("plan at its size %+v", p)
	}
	if _, err := s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, 7*day, 72*time.Hour, f.now, 6, 0); err == nil {
		t.Fatal("a cap of 0 accepted")
	}
}

func TestOffsiteExpirePlan_ReadsNoReportedColumnAndNoUploadTime(t *testing.T) {
	banned := regexp.MustCompile(`\b(start|stop)_|segment|lsn|uploaded_at|newest_`)
	for i, q := range planStatements {
		if m := banned.FindString(q); m != "" {
			t.Errorf("statement %d reads %q: %s", i, m, q)
		}
	}
	if len(planStatements) < 4 || strings.Count(strings.Join(planStatements, "\n"), "finished_at") != 2 {
		t.Fatalf("statements %v: finished_at is read for the anchor and for the clock alone", planStatements)
	}
}

func TestOffsiteExpirePlan_OnlyTheFiveKinds(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	orphan := "backup/" + f.stanza + "/20200101-000000F/pg_data/base/1/1"
	planRow(t, s, f.r, orphan, 2, f.now)
	planRow(t, s, f.r, "elsewhere/"+f.stanza+"/x", 2, f.now)
	// A key under a staying set's directory is never planned, whatever its number.
	planRow(t, s, f.r, "backup/"+f.stanza+"/"+f.labels[5]+"/pg_data/base/1/2", 2, f.now)
	p := f.plan(t, f.now, 7*day, 6, 2000)
	for _, k := range f.otherKeys {
		if slices.Contains(p.Keys, k) {
			t.Fatalf("planned %s", k)
		}
	}
	if !slices.Equal(p.Keys, append([]string{orphan}, f.keysOf(0, 1, 2)...)) {
		t.Fatalf("plan %v", p.Keys)
	}
}

func TestOffsiteExpirePlan_FloorOfZeroTakesTheNewestSetAWindowOld(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	p := f.plan(t, f.now, 2*day, 0, 2000)
	if p.Anchor != f.labels[8] {
		t.Fatalf("anchor %q, want the 2.5-day set", p.Anchor)
	}
	if p = f.plan(t, f.now.Add(365*day), 2*day, 0, 2000); p.Anchor != f.labels[9] {
		t.Fatalf("a year ahead: anchor %q, want the newest", p.Anchor)
	}
	if _, err := s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, 2*day, time.Hour, f.now, -1, 2000); err == nil {
		t.Fatal("a negative floor accepted")
	}
}

// --- merging what the record does not hold ---

func TestMergeUnrecorded_AsARebuildPageUnderTheJobsNumber(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	j := opsJob(t, s, r, "offsite-expire", "running", 77, time.Time{}, "")
	known := bsSegKey(st, "17-1", bsSeg(1, 1))
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(known, 1, "v1", bsT0)}, At: bsT0, Launch: 5})
	newKey := bsSegKey(st, "17-1", bsSeg(1, 2))
	must(t, s.MergeUnrecorded(ctx, r, []UnrecordedRow{{Key: known, VersionID: "vx", At: bsT0, Size: 3},
		{Key: newKey, VersionID: "v2", At: bsT0.Add(time.Hour), Size: 9}}, j))
	row, _, ok := bsObject(t, s, r, newKey)
	if !ok || row.SHA256 != nil || row.VersionID != "v2" || row.Size != 9 || !row.UploadedAt.Equal(bsT0.Add(time.Hour)) {
		t.Fatalf("merged row %+v", row)
	}
	if n := count(t, s, "select launch from offsite_object where key = $1", newKey); n != 77 {
		t.Fatalf("merged under %d", n)
	}
	if row, _, _ := bsObject(t, s, r, known); row.VersionID != "v1" || row.SHA256 == nil || count(t, s, "select launch from offsite_object where key = $1", known) != 5 {
		t.Fatalf("an existing row changed: %+v", row)
	}
	// A job of another subject is refused.
	r2, _ := bsProject(t, s, 2)
	other := opsJob(t, s, r2, "offsite-expire", "running", 78, time.Time{}, "")
	if err := s.MergeUnrecorded(ctx, r, []UnrecordedRow{{Key: "x", VersionID: "v", At: bsT0}}, other); err == nil {
		t.Fatal("merged under another subject's job")
	}
}

func TestMergeUnrecorded_ARowWithoutItsVersionIdIsRefused(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	j := opsJob(t, s, r, "offsite-expire", "running", 77, time.Time{}, "")
	k1, k2 := bsSegKey(st, "17-1", bsSeg(1, 1)), bsSegKey(st, "17-1", bsSeg(1, 2))
	if err := s.MergeUnrecorded(ctx, r, []UnrecordedRow{{Key: k1, VersionID: "v1", At: bsT0}, {Key: k2, At: bsT0}}, j); err == nil {
		t.Fatal("a row without its version id was merged")
	}
	if n := count(t, s, "select count(*) from offsite_object where subject = $1", r); n != 0 {
		t.Fatalf("%d rows written", n)
	}
	// Control: with the id it is there, and the copy's hash fills under that id.
	must(t, s.MergeUnrecorded(ctx, r, []UnrecordedRow{{Key: k2, VersionID: "v2", At: bsT0, Size: 10}}, j))
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(k2, 4, "v2", bsT0)}, At: bsT0, Launch: 80})
	if row, _, _ := bsObject(t, s, r, k2); row.VersionID != "v2" || row.SHA256 == nil {
		t.Fatalf("row %+v", row)
	}
}

func TestRecordUploads_AMarkedNameCreatedAgainIsBudgetedAndNumbered(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	k := bsSegKey(st, "17-1", bsSeg(1, 1))
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(k, 1, "v1", bsT0)}, At: bsT0, Launch: 10})
	must(t, s.PruneObjects(ctx, r, []string{k}, bsT0))
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(k, 2, "v2", bsT0)}, At: bsT0, Launch: 20})
	if n := count(t, s, "select count(*) from offsite_object where key = $1", k); n != 1 {
		t.Fatalf("%d rows", n)
	}
	if n := count(t, s, "select launch from offsite_object where key = $1", k); n != 20 {
		t.Fatalf("recorded again under %d", n)
	}
	if b := bsState(t, s, r); b.BytesToday != 20 || b.ObjectsToday != 2 {
		t.Fatalf("budget %d bytes, %d objects", b.BytesToday, b.ObjectsToday)
	}
	if ns, _ := s.ListNotices(ctx, r); len(ns) != 0 {
		t.Fatalf("notices %+v", ns)
	}
	// Control: recorded twice without a prune the first row stays.
	k2 := bsSegKey(st, "17-1", bsSeg(1, 2))
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(k2, 1, "v1", bsT0)}, At: bsT0, Launch: 30})
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(k2, 1, "v1", bsT0)}, At: bsT0, Launch: 40})
	if n := count(t, s, "select launch from offsite_object where key = $1", k2); n != 30 {
		t.Fatalf("recorded twice: launch %d", n)
	}
}

// --- the clock's guard ---

func TestRecordPass_LateOrEarlierPassSetsTheHold(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name         string
		next         time.Duration
		jumped, hold bool
	}{
		{"61 minutes late", 61 * time.Minute, true, true},
		{"a minute before the previous", -time.Minute, true, true},
		{"five minutes on", 5 * time.Minute, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t, testConfig())
			// The first pass ever: the hold, and not jumped.
			jumped, until, err := s.RecordPass(ctx, t0, time.Hour, 24*time.Hour)
			must(t, err)
			if jumped || until == nil || !until.Equal(t0.Add(24*time.Hour)) {
				t.Fatalf("first pass: jumped %v, hold %v", jumped, until)
			}
			sqlExec(t, s, "update node set clock_hold_until = null")
			now := t0.Add(tc.next)
			jumped, until, err = s.RecordPass(ctx, now, time.Hour, 24*time.Hour)
			must(t, err)
			if jumped != tc.jumped || (until != nil) != tc.hold || tc.hold && !until.Equal(now.Add(24*time.Hour)) {
				t.Fatalf("jumped %v, hold %v", jumped, until)
			}
			held, err := s.ClockHold(ctx, now)
			must(t, err)
			if held != tc.hold {
				t.Fatalf("ClockHold %v", held)
			}
			if tc.hold {
				if held, _ := s.ClockHold(ctx, now.Add(24*time.Hour)); held {
					t.Fatal("the hold stands at its end")
				}
			}
			var pass time.Time
			must(t, s.pool.QueryRow(ctx, "select pass_at from node").Scan(&pass))
			if !pass.Equal(now) {
				t.Fatalf("pass_at %v", pass)
			}
		})
	}
}

// --- the purge ---

func TestPurgeAllowed_StateAndWait(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	now := memberDBNow(t, s)
	allowed := func(r string, at time.Time) (bool, string) {
		t.Helper()
		ok, reason, err := s.PurgeAllowed(ctx, r, 7*day, at)
		must(t, err)
		return ok, reason
	}
	want := func(r string, at time.Time, ok bool, reason string) {
		t.Helper()
		if g, gr := allowed(r, at); g != ok || gr != reason {
			t.Fatalf("%s: %v %q, want %v %q", r, g, gr, ok, reason)
		}
	}
	prep := func(r string) {
		must(t, s.EnsureBackupState(ctx, r))
		sqlExec(t, s, "update backup_state set rebuild_epoch = 1, offsite_purge = true where subject = $1", r)
	}
	// An active project with the flag.
	a := newActive(t, s, 1)
	prep(a)
	must(t, s.MarkPurgeSeen(ctx, a, now.Add(-8*day)))
	want(a, now, false, "state")
	// Purged in an older epoch: allowed once the wait has passed.
	p := newActive(t, s, 2)
	markDeleted(t, s, p)
	must(t, s.MarkPurged(ctx, p))
	prep(p)
	sqlExec(t, s, "update project set epoch = 0 where ref = $1", p)
	want(p, now, false, "wait") // first seen: not yet
	must(t, s.MarkPurgeSeen(ctx, p, now.Add(-6*day)))
	must(t, s.MarkPurgeSeen(ctx, p, now.Add(-30*day))) // only when unset
	want(p, now, false, "wait")
	want(p, now.Add(day+time.Second), true, "")
	// Aborted in an older epoch: state; in this epoch: allowed.
	b := ref(3)
	mustCreate(t, s, b)
	must(t, s.MarkAborted(ctx, b))
	prep(b)
	must(t, s.MarkPurgeSeen(ctx, b, now.Add(-8*day)))
	want(b, now, true, "")
	sqlExec(t, s, "update project set epoch = 0 where ref = $1", b)
	want(b, now, false, "state")
	// --now waives the wait; --keep clears the obligation.
	must(t, s.SetPurgeWait(ctx, p, false, true))
	want(p, now, true, "")
	must(t, s.SetPurgeWait(ctx, p, true, false))
	want(p, now, false, "state")
	wantErr(t, s.SetPurgeWait(ctx, p, true, true), ErrConflict)
	wantErr(t, s.SetPurgeWait(ctx, ref(9), true, false), ErrNotFound)
	// Not rebuilt.
	sqlExec(t, s, "update backup_state set rebuild_epoch = 0 where subject = $1", b)
	_, _, err := s.PurgeAllowed(ctx, b, 7*day, now)
	wantErr(t, err, ErrNotRebuilt)
	// A purge that listed nothing current clears the flag.
	must(t, s.ClearOffsitePurge(ctx, a))
	if bsState(t, s, a).OffsitePurge {
		t.Fatal("flag kept")
	}
	// Without the flag there is no wait to waive.
	if err := s.SetPurgeWait(ctx, a, false, true); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "no off-site purge") {
		t.Fatalf("--now without the flag: %v", err)
	}
}

func TestPurgeAllowed_AJobTimeInTheFutureIsErrClock(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	now := memberDBNow(t, s)
	p := newActive(t, s, 1)
	must(t, s.EnsureBackupState(ctx, p))
	markDeleted(t, s, p)
	must(t, s.MarkPurged(ctx, p))
	sqlExec(t, s, "update backup_state set rebuild_epoch = 1, offsite_purge = true, offsite_purge_seen_at = $2 where subject = $1", p, now.Add(-30*day))
	j := opsJob(t, s, p, "push", "done", 5, now.Add(time.Hour), `{}`)
	_, _, err := s.PurgeAllowed(ctx, p, 7*day, now)
	wantErr(t, err, ErrClock)
	sqlExec(t, s, "update backup_job set started_at = $2, finished_at = $2, created_at = $2 where id = $1", j, now.Add(-time.Minute))
	ok, reason, err := s.PurgeAllowed(ctx, p, 7*day, now)
	if err != nil || !ok || reason != "" {
		t.Fatalf("control: %v %q %v", ok, reason, err)
	}
}

// --- pruning ---

func TestPruneObjects_MarksTheSetRemovedAtItsFirstKey(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	f := newPlanFix(t, s)
	at := f.now.Truncate(time.Microsecond)
	must(t, s.PruneObjects(ctx, f.r, []string{f.setKeys[0][2], f.setKeys[1][4]}, at))
	if _, _, ok := bsObject(t, s, f.r, f.setKeys[0][2]); ok {
		t.Fatal("row kept")
	}
	removed := func(i int) *time.Time {
		var at *time.Time
		must(t, s.pool.QueryRow(ctx, "select offsite_removed_at from backup_set where label = $1", f.labels[i]).Scan(&at))
		return at
	}
	timeIs(t, "set 0", removed(0), at)
	if removed(1) != nil { // a segment names no set
		t.Fatal("set 1 marked by a segment")
	}
	must(t, s.PruneObjects(ctx, f.r, []string{f.setKeys[0][0]}, at.Add(time.Hour)))
	timeIs(t, "set 0 again", removed(0), at)
}

func infoRow(t *testing.T, s *Store, subject, name, ver string, at time.Time) {
	t.Helper()
	sqlExec(t, s, "insert into offsite_info_version (subject, name, version_id, sha256, uploaded_at) values ($1, $2, $3, $4, $5)",
		subject, name, ver, bsHash(1), at)
}

func infoVers(t *testing.T, s *Store, subject string) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), "select name || ':' || version_id from offsite_info_version where subject = $1 order by 1", subject)
	must(t, err)
	var out []string
	for rows.Next() {
		var v string
		must(t, rows.Scan(&v))
		out = append(out, v)
	}
	return out
}

func TestPruneInfoVersions_KeepsEachNamesNewest(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	for i := 0; i < 3; i++ {
		infoRow(t, s, r, "backup.info", fmt.Sprintf("b%d", i), bsT0.Add(time.Duration(i)*day))
		infoRow(t, s, r, "archive.info", fmt.Sprintf("a%d", i), bsT0.Add(time.Duration(i)*day))
	}
	n, err := s.PruneInfoVersions(ctx, r, bsT0.Add(day+time.Hour))
	must(t, err)
	if want := []string{"archive.info:a2", "backup.info:b2"}; n != 4 || !slices.Equal(infoVers(t, s, r), want) {
		t.Fatalf("pruned %d, kept %v", n, infoVers(t, s, r))
	}
	n, err = s.PruneInfoVersions(ctx, r, bsT0.Add(365*day))
	must(t, err)
	if n != 0 || len(infoVers(t, s, r)) != 2 {
		t.Fatalf("the newest pruned: %d", n)
	}
}

// infoFix: seven replicated sets, set i listed by version v<i> of
// backup.info, five expired at the same location a day and a half after
// their listing; v7 is a later upload.
func infoFix(t *testing.T, s *Store) (r string, labels []string) {
	t.Helper()
	r, _ = bsProject(t, s, 1)
	for i := 0; i < 8; i++ {
		at := bsT0.Add(time.Duration(i) * day)
		infoRow(t, s, r, "backup.info", fmt.Sprintf("v%d", i), at)
		if i == 7 {
			break
		}
		label := fmt.Sprintf("202611%02d-120000F", i+1)
		labels = append(labels, label)
		var local *time.Time
		if i < 5 {
			l := at.Add(36 * time.Hour)
			local = &l
		}
		j := opsJob(t, s, r, "backup", "done", int64(i+1), at, `{}`)
		sqlExec(t, s, `insert into backup_set (subject, label, tli, start_segment, stop_segment, start_lsn, stop_lsn, start_at, stop_at,
			job_id, replicated, listed_at, expired_local_at) values ($1, $2, 1, $3, $3, '0/1', '0/2', $4, $4, $5, true, $4, $6)`,
			r, label, bsSeg(1, i), at, j, local)
	}
	return r, labels
}

func TestPruneInfoVersions_KeepsTheFetchVersionOfEveryStayingSet(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, labels := infoFix(t, s)
	n, err := s.PruneInfoVersions(ctx, r, bsT0.Add(365*day))
	must(t, err)
	if n != 0 {
		t.Fatalf("pruned %d", n)
	}
	for i, l := range labels {
		asListed, whileLocal, err := s.InfoVersionsFor(ctx, r, l)
		must(t, err)
		if len(asListed) != 1 || asListed[0].VersionID != fmt.Sprintf("v%d", i) ||
			len(whileLocal) != 1 || whileLocal[0].VersionID != fmt.Sprintf("v%d", i+1) {
			t.Fatalf("set %d: %+v, %+v", i, asListed, whileLocal)
		}
	}
	// Control: the candidates of a set removed off-site are pruned.
	sqlExec(t, s, "update backup_set set offsite_removed_at = now() where label = $1", labels[0])
	n, err = s.PruneInfoVersions(ctx, r, bsT0.Add(365*day))
	must(t, err)
	if n != 1 || slices.Contains(infoVers(t, s, r), "backup.info:v0") {
		t.Fatalf("pruned %d, kept %v", n, infoVers(t, s, r))
	}
}

// --- reads ---

func TestInfoVersionsAsOf_NewestAtOrBefore(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	infoRow(t, s, r, "backup.info", "b0", bsT0)
	infoRow(t, s, r, "backup.info", "b1", bsT0.Add(time.Hour))
	infoRow(t, s, r, "archive.info", "a0", bsT0.Add(-time.Hour))
	infoRow(t, s, r, "archive.info", "a1", bsT0.Add(2*time.Hour))
	vs, err := s.InfoVersionsAsOf(ctx, r, bsT0.Add(time.Hour))
	must(t, err)
	if len(vs) != 2 || vs[0].VersionID != "a0" || vs[1].VersionID != "b1" {
		t.Fatalf("%+v", vs)
	}
	vs, err = s.InfoVersionsAsOf(ctx, r, bsT0.Add(-2*time.Hour))
	must(t, err)
	if len(vs) != 0 {
		t.Fatalf("before every upload: %+v", vs)
	}
}

func TestSetsListedBy_UsesTheListingTime(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, labels := infoFix(t, s)
	sqlExec(t, s, "update backup_set set stop_at = $2 where label = $1", labels[2], bsT0.Add(-30*day))
	sqlExec(t, s, "update backup_set set replicated = false where label = $1", labels[1])
	sqlExec(t, s, "update backup_set set offsite_removed_at = now() where label = $1", labels[0])
	got, err := s.SetsListedBy(ctx, r, bsT0.Add(2*day))
	must(t, err)
	if !slices.Equal(got, labels[2:3]) {
		t.Fatalf("listed by %v: %v", bsT0.Add(2*day), got)
	}
}

func TestInfoVersionsFor_AsListedAndWhileLocal(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, labels := infoFix(t, s)
	// Set 1 expired before any later upload: no second candidate.
	sqlExec(t, s, "update backup_set set expired_local_at = listed_at + interval '1 hour' where label = $1", labels[1])
	asListed, whileLocal, err := s.InfoVersionsFor(ctx, r, labels[1])
	must(t, err)
	if len(asListed) != 1 || asListed[0].VersionID != "v1" || len(whileLocal) != 0 {
		t.Fatalf("%+v %+v", asListed, whileLocal)
	}
	// Two later uploads while still local: the oldest.
	infoRow(t, s, r, "backup.info", "v2b", bsT0.Add(2*day+time.Hour))
	_, whileLocal, err = s.InfoVersionsFor(ctx, r, labels[2])
	must(t, err)
	if len(whileLocal) != 1 || whileLocal[0].VersionID != "v2b" {
		t.Fatalf("%+v", whileLocal)
	}
	_, _, err = s.InfoVersionsFor(ctx, r, "20000101-000000F")
	wantErr(t, err, ErrNotFound)
}

func TestSchedule_OneRowPerSubject(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	now := memberDBNow(t, s)
	a, _ := bsProject(t, s, 1)
	b, _ := bsProject(t, s, 2)
	c, _ := bsProject(t, s, 3)
	must(t, s.EnsureBackupState(ctx, "cp"))
	opsJob(t, s, a, "push", "done", 1, now.Add(-time.Hour), `{}`)
	opsJob(t, s, a, "push", "failed", 2, now.Add(-time.Minute), `{}`)
	opsJob(t, s, a, "push", "queued", 0, time.Time{}, "")
	failed := opsJob(t, s, a, "backup", "failed", 3, now.Add(-time.Minute), `{}`)
	queued := opsJob(t, s, a, "backup", "queued", 0, time.Time{}, "")
	old := opsJob(t, s, a, "backup", "done", 4, now.Add(-time.Minute), `{}`)
	// FullsToday counts by UTC day: the two of today are created at the day's
	// first instant, the old one at the last instant before it, whatever the hour.
	sqlExec(t, s, "update backup_job set created_at = date_trunc('day', now(), 'UTC') where id = any($1)", []int64{failed, queued})
	sqlExec(t, s, "update backup_job set created_at = date_trunc('day', now(), 'UTC') - interval '1 microsecond' where id = $1", old)
	opsJob(t, s, b, "push", "failed", 5, now.Add(-time.Hour), `{}`)
	opsJob(t, s, b, "push", "done", 6, now.Add(-time.Minute), `{}`)
	must(t, s.SetFullDue(ctx, a, true))
	must(t, s.MarkSchedule(ctx, a, "check", now, true))
	must(t, s.MarkSchedule(ctx, b, "check", now, false))
	must(t, s.MarkSchedule(ctx, a, "verify", now, false))
	for _, w := range []string{"expire", "offsite-expire", "spool-drop", "canary", "deadman"} {
		must(t, s.MarkSchedule(ctx, c, w, now, true))
	}
	wantErr(t, s.MarkSchedule(ctx, c, "other", now, true), ErrConflict)
	wantErr(t, s.MarkSchedule(ctx, ref(9), "check", now, true), ErrNotFound)
	rows, err := s.Schedule(ctx)
	must(t, err)
	m := map[string]SubjectSchedule{}
	for _, r := range rows {
		m[r.Subject] = r
	}
	if len(rows) != 4 || len(m) != 4 || m["cp"].ProjectState != "" || m[a].ProjectState != "active" {
		t.Fatalf("rows %+v", rows)
	}
	ra, rb, rc := m[a], m[b], m[c]
	if ra.FullsToday != 2 || !ra.LastPushFailed || rb.LastPushFailed || rc.LastPushFailed || !ra.FullDue || rb.FullDue {
		t.Fatalf("a %+v\nb %+v\nc %+v", ra, rb, rc)
	}
	if ra.LastCheckOK == nil || rb.LastCheckOK != nil || ra.VerifyOK == nil || *ra.VerifyOK || ra.LastVerifyAt == nil {
		t.Fatalf("a %+v\nb %+v", ra, rb)
	}
	if ra.LastPushLaunched == nil || !ra.LastPushLaunched.Equal(now.Add(-2*time.Minute)) {
		t.Fatalf("last push launched %v", ra.LastPushLaunched)
	}
	for _, p := range []*time.Time{rc.LastExpireAt, rc.LastOffsiteExpireAt, rc.SpoolDroppedAt, rc.CanaryAt, rc.DeadmanAt} {
		if p == nil {
			t.Fatalf("c %+v", rc)
		}
	}
	n, err := s.DropsSince(ctx, now.Add(-time.Hour))
	must(t, err)
	if n != 0 {
		t.Fatalf("drops %d", n)
	}
	opsJob(t, s, a, "drop-spool", "queued", 0, time.Time{}, "")
	if n, _ := s.DropsSince(ctx, now.Add(-time.Hour)); n != 1 {
		t.Fatalf("drops %d", n)
	}
}

func TestScheduleSets(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	rows, err := s.Schedule(context.Background())
	must(t, err)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	if r.Sets != 10 || r.SetsNotExpiredLocal != 2 || !r.NewestSetReplicated || r.NewestSetFinished == nil ||
		!r.NewestSetFinished.Equal(f.now.Add(-36*time.Hour)) {
		t.Fatalf("%+v", r)
	}
}
