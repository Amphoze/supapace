package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/poolcfg"
)

const roLogin = "supabase_read_only_user"

func TestValidate_AllowListNeedsTheNodesAddresses(t *testing.T) {
	c := testConfig()
	own := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.7")}
	withList := func(l ...string) ProjectSettings { return ProjectSettings{Pooler: &PoolerSettings{AllowList: l}} }
	// Control: while restrictions are not offered a list is refused first,
	// whatever the addresses.
	for _, o := range [][]netip.Addr{nil, own} {
		err := withList("203.0.113.0/24").Validate(c, o, 120)
		if err == nil || !strings.Contains(err.Error(), "not offered") {
			t.Fatalf("flag false, addresses %v: %v", o, err)
		}
	}
	poolcfg.RestrictionsOffered = true
	t.Cleanup(func() { poolcfg.RestrictionsOffered = false })
	if err := withList("203.0.113.0/24").Validate(c, nil, 120); err == nil || !strings.Contains(err.Error(), "addresses") {
		t.Fatalf("a list without the node's addresses: %v", err)
	}
	err := withList("198.51.100.0/24").Validate(c, own, 120)
	if err == nil || !strings.Contains(err.Error(), "entry 1 of 1") || strings.Contains(err.Error(), "198.51.100.7") {
		t.Fatalf("a list holding a node address: %v", err)
	}
	must(t, withList("203.0.113.0/24").Validate(c, own, 120))
	// A document without a list never looks at them.
	must(t, ProjectSettings{Rate: &RateSettings{RPS: 10, Burst: 20}}.Validate(c, nil, 120))
}

func TestValidate_Bounds(t *testing.T) {
	c := testConfig()
	names := func(n int) []string {
		l := make([]string, n)
		for i := range l {
			l[i] = fmt.Sprintf("s%d", i)
		}
		return l
	}
	for _, tc := range []struct {
		name string
		p    ProjectSettings
		ok   bool
	}{
		{"empty", ProjectSettings{}, true},
		{"schemas", ProjectSettings{API: &APISettings{Schemas: []string{"public", "api_v1"}, ExtraSearchPath: []string{"extensions"}, MaxRows: 1000}}, true},
		{"16 schemas", ProjectSettings{API: &APISettings{Schemas: names(16)}}, true},
		{"17 schemas", ProjectSettings{API: &APISettings{Schemas: names(17)}}, false},
		{"pg_ schema", ProjectSettings{API: &APISettings{Schemas: []string{"pg_catalog"}}}, false},
		{"reserved schema", ProjectSettings{API: &APISettings{ExtraSearchPath: []string{"supapace_pooler"}}}, false},
		{"information_schema", ProjectSettings{API: &APISettings{Schemas: []string{"information_schema"}}}, false},
		{"bad name", ProjectSettings{API: &APISettings{Schemas: []string{"Public"}}}, false},
		{"max rows", ProjectSettings{API: &APISettings{MaxRows: 1_000_001}}, false},
		{"max rows negative", ProjectSettings{API: &APISettings{MaxRows: -1}}, false},
		{"pool 16 at 120", ProjectSettings{Pooler: &PoolerSettings{PoolSize: 16, MaxClients: 1000}}, true},
		{"pool 17 at 120", ProjectSettings{Pooler: &PoolerSettings{PoolSize: 17}}, false},
		{"pool negative", ProjectSettings{Pooler: &PoolerSettings{PoolSize: -1}}, false},
		{"clients 1001", ProjectSettings{Pooler: &PoolerSettings{MaxClients: 1001}}, false},
		{"rate", ProjectSettings{Rate: &RateSettings{RPS: 100000, Burst: 1000000}}, true},
		{"rate 0", ProjectSettings{Rate: &RateSettings{RPS: 0, Burst: 0}}, false},
		{"burst below rps", ProjectSettings{Rate: &RateSettings{RPS: 10, Burst: 9}}, false},
		{"burst above 10x", ProjectSettings{Rate: &RateSettings{RPS: 10, Burst: 101}}, false},
		{"aud", ProjectSettings{Aud: []string{"a", strings.Repeat("b", 255)}}, true},
		{"aud 9", ProjectSettings{Aud: names(9)}, false},
		{"aud long", ProjectSettings{Aud: []string{strings.Repeat("b", 256)}}, false},
		{"aud control", ProjectSettings{Aud: []string{"a\x01"}}, false},
		{"aud empty", ProjectSettings{Aud: []string{""}}, false},
		{"stopped", ProjectSettings{Stopped: true}, true},
	} {
		if err := tc.p.Validate(c, nil, 120); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok %v", tc.name, err, tc.ok)
		}
	}
	// The pool size follows max_connections.
	if err := (ProjectSettings{Pooler: &PoolerSettings{PoolSize: 5}}).Validate(c, nil, 75); err == nil {
		t.Error("pool size 5 at max_connections 75 accepted")
	}
}

func setOps(t *testing.T, s *Store, r string) []Operation {
	t.Helper()
	ops, err := s.ListOperations(context.Background(), r)
	must(t, err)
	return ops
}

func TestSubmitSettings_RefusesAStaleBase(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	got, err := s.GetSettings(ctx, r)
	must(t, err)
	if fmt.Sprint(got) != fmt.Sprint(ProjectSettings{}) {
		t.Fatalf("new project's settings %+v", got)
	}
	target := ProjectSettings{Rate: &RateSettings{RPS: 5, Burst: 10}, Stopped: true}
	id, err := s.SubmitSettings(ctx, r, ProjectSettings{}, target)
	must(t, err)
	op := wantOpState(t, s, id, "pending")
	var params struct{ Base, Target ProjectSettings }
	must(t, json.Unmarshal(op.Params, &params))
	if op.Kind != "settings" || params.Target.Rate == nil || params.Target.Rate.RPS != 5 || !params.Target.Stopped {
		t.Fatalf("operation %+v, params %s", op, op.Params)
	}
	must(t, s.StartOperation(ctx, id))
	must(t, s.StoreSettings(ctx, id, target))
	must(t, s.FinishOperation(ctx, id, "done", ""))
	got, err = s.GetSettings(ctx, r)
	must(t, err)
	if !got.Stopped || got.Rate == nil || got.Rate.Burst != 10 {
		t.Fatalf("stored settings %+v", got)
	}
	// A second change merged onto the old document is refused.
	_, err = s.SubmitSettings(ctx, r, ProjectSettings{}, ProjectSettings{Aud: []string{"x"}})
	if wantErr(t, err, ErrConflict); !strings.Contains(err.Error(), "settings changed meanwhile") {
		t.Fatalf("stale base: %v", err)
	}
	// Control: merged onto the stored one it is accepted.
	_, err = s.SubmitSettings(ctx, r, target, ProjectSettings{Aud: []string{"x"}})
	must(t, err)
	// A finished operation stores nothing more.
	wantErr(t, s.StoreSettings(ctx, id, ProjectSettings{}), ErrConflict)
}

func TestSubmitSettings_RefusesBesideAnOpenOperation(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	rid, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
	must(t, err)
	_, err = s.SubmitSettings(ctx, r, ProjectSettings{}, ProjectSettings{Stopped: true})
	wantErr(t, err, ErrConflict)
	// A project left restarting by a failed restart is not taken over.
	must(t, s.StartOperation(ctx, rid))
	must(t, s.BeginRestart(ctx, r, 2, defaultConfig))
	must(t, s.FinishOperation(ctx, rid, "failed", "internal: boom"))
	_, err = s.SubmitSettings(ctx, r, ProjectSettings{}, ProjectSettings{Stopped: true})
	if wantErr(t, err, ErrConflict); !strings.Contains(err.Error(), "restarting") {
		t.Fatalf("restarting: %v", err)
	}
	if n := len(setOps(t, s, r)); n != 2 {
		t.Fatalf("%d operations", n)
	}
	wantErr(t, func() error {
		_, err := s.SubmitSettings(ctx, ref(9), ProjectSettings{}, ProjectSettings{})
		return err
	}(), ErrNotFound)
}

func TestSubmitRekey_QueuesBesideAnOpenOperationOnce(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, queued, err := s.SubmitRekey(ctx, r, "postgres")
	must(t, err)
	if queued || id == 0 {
		t.Fatalf("free project: id %d, queued %v", id, queued)
	}
	op := wantOpState(t, s, id, "pending")
	if op.Kind != "rekey-login" || !strings.Contains(string(op.Params), `"login": "postgres"`) {
		t.Fatalf("operation %+v", op)
	}
	// Beside the open re-key both logins queue, each once.
	for i := 0; i < 2; i++ {
		for _, l := range []string{roLogin, "postgres"} {
			id, queued, err := s.SubmitRekey(ctx, r, l)
			must(t, err)
			if !queued || id != 0 {
				t.Fatalf("beside an open operation: id %d, queued %v", id, queued)
			}
		}
	}
	p, err := s.PendingRekeys(ctx)
	must(t, err)
	if len(p) != 2 || p[0].Ref != r || p[0].Login != roLogin || p[1].Login != "postgres" || p[0].Since.IsZero() {
		t.Fatalf("pending %+v", p)
	}
	if n := len(setOps(t, s, r)); n != 2 { // the create and the re-key
		t.Fatalf("%d operations", n)
	}
	// A login that is not a role name is refused.
	_, _, err = s.SubmitRekey(ctx, r, "x;y")
	wantErr(t, err, ErrConflict)
	// A project left restarting by a failed restart has no open operation,
	// and is not taken over: the re-key waits.
	r2 := newActive(t, s, 2)
	failRestart(t, s, r2, 1)
	if id, queued, err := s.SubmitRekey(ctx, r2, "postgres"); err != nil || !queued || id != 0 {
		t.Fatalf("restarting: id %d, queued %v, %v", id, queued, err)
	}
}

func TestFailedRekeys_NewestOperationOfTheLoginOnly(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	run := func(login, end string) int64 {
		id, queued, err := s.SubmitRekey(ctx, r, login)
		must(t, err)
		if queued {
			t.Fatal("queued")
		}
		must(t, s.StartOperation(ctx, id))
		must(t, s.FinishOperation(ctx, id, end, map[string]string{"failed": "internal: boom"}[end]))
		return id
	}
	failed := func() []PendingRekey {
		f, err := s.FailedRekeys(ctx)
		must(t, err)
		return f
	}
	run("postgres", "failed")
	run("postgres", "done")
	if f := failed(); len(f) != 0 {
		t.Fatalf("a failed one followed by a done one: %+v", f)
	}
	run(roLogin, "done")
	id := run(roLogin, "failed")
	f := failed()
	if len(f) != 1 || f[0].Ref != r || f[0].Login != roLogin || !f[0].Since.Equal(opState(t, s, id).UpdatedAt) {
		t.Fatalf("a done one followed by a failed one: %+v", f)
	}
}

func promoteSecrets(t *testing.T, s *Store, r, name string) {
	t.Helper()
	ctx := context.Background()
	must(t, s.PutSecret(ctx, r, name, []byte("n-old"), []byte("old")))
	must(t, s.PutSecret(ctx, r, name+".next", []byte("n-new"), []byte("new")))
}

func secretValue(t *testing.T, s *Store, r, name string) string {
	t.Helper()
	_, ct, err := s.GetSecret(context.Background(), r, name)
	if err != nil {
		return err.Error()
	}
	return string(ct)
}

func TestPromoteNextSecret_OneTransactionAndIdempotent(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	name := "pg.postgres.password"
	promoteSecrets(t, s, r, name)
	sqlExec(t, s, "update project set rekey_pending = '[{\"login\":\"postgres\",\"since\":\"2026-01-01T00:00:00Z\"}]' where ref = $1", r)
	// The last statement fails: nothing of the swap stays.
	sqlExec(t, s, `create function no_pending() returns trigger language plpgsql as $$ begin raise exception 'refused'; end $$`)
	sqlExec(t, s, `create trigger no_pending before update of rekey_pending on project for each row execute function no_pending()`)
	if err := s.PromoteNextSecret(ctx, r, name, "postgres"); err == nil {
		t.Fatal("promoted through a failing statement")
	}
	if secretValue(t, s, r, name) != "old" || secretValue(t, s, r, name+".next") != "new" {
		t.Fatal("a failed promotion left part of its writes")
	}
	sqlExec(t, s, "drop trigger no_pending on project")
	must(t, s.PromoteNextSecret(ctx, r, name, "postgres"))
	n, ct, err := s.GetSecret(ctx, r, name)
	must(t, err)
	if string(ct) != "new" || string(n) != "n-new" {
		t.Fatalf("secret %q %q", n, ct)
	}
	wantErr(t, func() error { _, _, err := s.GetSecret(ctx, r, name+".next"); return err }(), ErrNotFound)
	if p, _ := s.PendingRekeys(ctx); len(p) != 0 {
		t.Fatalf("still pending %+v", p)
	}
	// A second call finds no .next and changes nothing.
	must(t, s.PromoteNextSecret(ctx, r, name, "postgres"))
	if secretValue(t, s, r, name) != "new" {
		t.Fatal("a second call changed the secret")
	}
}

func TestPromoteNextSecret_ReadOnlyLoginOwesTheCleanupAgain(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	memberSetDelay(t, s, time.Hour)
	r := newActive(t, s, 1)
	name := "pg." + roLogin + ".password"
	// The converger had removed the record: it is there again, due after the delay.
	promoteSecrets(t, s, r, name)
	must(t, s.PromoteNextSecret(ctx, r, name, roLogin))
	row, ok := memberCleanupRow(t, s, r)
	if !ok {
		t.Fatal("no clean-up record")
	}
	memberNear(t, "due", row.Due, memberDBNow(t, s).Add(time.Hour), 30*time.Second)
	// An existing one keeps the later due and is reset.
	later := memberDBNow(t, s).Add(48 * time.Hour).Truncate(time.Microsecond)
	sqlExec(t, s, "update readonly_cleanup set due = $2, due_fixed = true, failures = 3 where ref = $1", r, later)
	sqlExec(t, s, "delete from secret where ref = $1", r)
	promoteSecrets(t, s, r, name)
	must(t, s.PromoteNextSecret(ctx, r, name, roLogin))
	row, _ = memberCleanupRow(t, s, r)
	if !row.Due.Equal(later) || row.DueFixed || row.Failures != 0 {
		t.Fatalf("existing record after the promotion: %+v", row)
	}
	// A second call writes nothing.
	sqlExec(t, s, "update readonly_cleanup set failures = 2 where ref = $1", r)
	must(t, s.PromoteNextSecret(ctx, r, name, roLogin))
	if row, _ = memberCleanupRow(t, s, r); row.Failures != 2 {
		t.Fatal("a second call wrote the record")
	}
	// For postgres nothing is written.
	r2 := newActive(t, s, 2)
	promoteSecrets(t, s, r2, "pg.postgres.password")
	must(t, s.PromoteNextSecret(ctx, r2, "pg.postgres.password", "postgres"))
	if _, ok := memberCleanupRow(t, s, r2); ok {
		t.Fatal("a re-key of postgres owed the clean-up")
	}
}

func TestAddRestorePoint_RefusesATimelineThatIsNotTheNewestRecorded(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	must(t, s.AddRestorePoint(ctx, r, "before-1", "0/1000000", 1))
	op := bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op, nil)
	must(t, err)
	must(t, s.ConfirmTimeline(ctx, r, op, 2))
	op2 := bsOp(t, s, r)
	_, err = s.BeginRecoveryAttempt(ctx, r, st, op2, []int{2})
	must(t, err) // timeline 3 pending: not recorded
	for _, tli := range []int{1, 3, 4} {
		wantErr(t, s.AddRestorePoint(ctx, r, "p", "0/2000000", tli), ErrConflict)
	}
	must(t, s.AddRestorePoint(ctx, r, "after-2", "0/2000000", 2))
	wantErr(t, s.AddRestorePoint(ctx, r, "after-2", "0/3000000", 2), ErrConflict)
	wantErr(t, s.AddRestorePoint(ctx, r, "Bad", "0/3000000", 2), ErrConflict)
	wantErr(t, s.AddRestorePoint(ctx, r, "x", "not an lsn", 2), ErrConflict)
	p, err := s.GetRestorePoint(ctx, r, "before-1")
	must(t, err)
	if p.LSN != "0/1000000" || p.TLI != 1 || p.Ref != r || p.CreatedAt.IsZero() {
		t.Fatalf("restore point %+v", p)
	}
	_, err = s.GetRestorePoint(ctx, r, "none")
	wantErr(t, err, ErrNotFound)
	l, err := s.ListRestorePoints(ctx, r)
	must(t, err)
	if len(l) != 2 || l[0].Name != "after-2" || l[1].Name != "before-1" {
		t.Fatalf("list %+v", l)
	}
}

func TestRecordIssuanceAndReadOnlySince(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	must(t, s.RecordIssuance(ctx, r, "postgres", "owner", "operator"))
	wantErr(t, s.RecordIssuance(ctx, r, "postgres", "owner", strings.Repeat("x", 256)), ErrConflict)
	wantErr(t, s.RecordIssuance(ctx, r, "", "owner", "operator"), ErrConflict)
	wantErr(t, s.RecordIssuance(ctx, ref(9), "postgres", "owner", "operator"), ErrNotFound)
	if n := count(t, s, "select count(*) from issuance where ref = $1 and login = 'postgres' and asked_by = 'operator'", r); n != 1 {
		t.Fatalf("%d issuance rows", n)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	must(t, s.SetReadOnlySince(ctx, r, &at))
	if n := count(t, s, "select count(*) from project where ref = $1 and read_only_since = $2", r, at); n != 1 {
		t.Fatal("read_only_since not set")
	}
	must(t, s.SetReadOnlySince(ctx, r, nil))
	if n := count(t, s, "select count(*) from project where ref = $1 and read_only_since is null", r); n != 1 {
		t.Fatal("read_only_since not cleared")
	}
	wantErr(t, s.SetReadOnlySince(ctx, ref(9), nil), ErrNotFound)
}
