package store

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/dashfile"
)

// memberTestN is the base64url modulus of one RSA key, generated once.
var memberTestN = sync.OnceValue(func() string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.N.Bytes())
})

// memberJWKS is a key set of n keys with kids kidPrefix+i, all of one modulus.
func memberJWKS(n int, kidPrefix string) json.RawMessage {
	var keys []string
	for i := range n {
		keys = append(keys, fmt.Sprintf(`{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":"AQAB"}`,
			kidPrefix+fmt.Sprint(i), memberTestN()))
	}
	return json.RawMessage(`{"keys":[` + strings.Join(keys, ",") + `]}`)
}

func memberIssuer() DashboardIssuer {
	return DashboardIssuer{Issuer: "https://issuer.test", ClientID: "supapace", AuthorizeURL: "https://issuer.test/authorize",
		SessionSeconds: MaxSessionSeconds, JWKS: memberJWKS(1, "k")}
}

func memberAdd(t *testing.T, s *Store, r, sub, role string) {
	t.Helper()
	must(t, s.AddMember(context.Background(), Member{Ref: r, Issuer: "https://issuer.test", Subject: sub, Role: role}))
}

func memberChange(s *Store, r, sub, from, to string) error {
	return s.ChangeMember(context.Background(), r, "https://issuer.test", sub, from, to)
}

// memberDBNow is the database's clock.
func memberDBNow(t *testing.T, s *Store) time.Time {
	t.Helper()
	var now time.Time
	must(t, s.pool.QueryRow(context.Background(), "select now()").Scan(&now))
	return now
}

// memberCleanupRow is the clean-up record of r; ok is false without one.
func memberCleanupRow(t *testing.T, s *Store, r string) (row ReadOnlyCleanup, ok bool) {
	t.Helper()
	row.Ref = r
	err := s.pool.QueryRow(context.Background(), "select due, due_fixed, next_try, failures from readonly_cleanup where ref = $1", r).
		Scan(&row.Due, &row.DueFixed, &row.NextTry, &row.Failures)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, false
	}
	must(t, err)
	return row, true
}

// memberNear fails unless got is within [want-slack, want].
func memberNear(t *testing.T, what string, got, want time.Time, slack time.Duration) {
	t.Helper()
	if got.After(want) || got.Before(want.Add(-slack)) {
		t.Fatalf("%s %v, want %v (at most %v earlier)", what, got, want, slack)
	}
}

// memberSetDelay sets the clean-up delay for one test.
func memberSetDelay(t *testing.T, s *Store, d time.Duration) {
	s.SetCleanupDelay(d)
	t.Cleanup(func() { s.SetCleanupDelay(0) })
}

// memberFile renders a table into the dashboard file as its writer does: the
// test of the store's rules is that whatever it accepted marshals.
func memberFile(tbl DashboardTable) dashfile.File {
	f := dashfile.File{Generation: 1, Node: "local", StudioDomain: "studio.test", Studio: "http://10.212.0.3:3000",
		Projects: map[string]dashfile.Project{}}
	if is := tbl.Issuer; is != nil {
		var set struct{ Keys []dashfile.IssuerKey }
		_ = json.Unmarshal(is.JWKS, &set)
		f.Issuer = &dashfile.Issuer{Iss: is.Issuer, ClientID: is.ClientID, AuthorizeURL: is.AuthorizeURL,
			EndSessionURL: is.EndSessionURL, SessionSeconds: int64(is.SessionSeconds), Keys: set.Keys}
	}
	for _, r := range tbl.Revoked {
		f.Revoked = append(f.Revoked, dashfile.Revocation{Iss: r.Issuer, Sub: r.Subject, NotBefore: r.NotBefore.Unix() + 1})
	}
	for _, p := range tbl.Projects {
		var ms []dashfile.Member
		for _, m := range p.Members {
			ms = append(ms, dashfile.Member{Iss: m.Issuer, Sub: m.Subject, Role: m.Role})
		}
		f.Projects[p.Ref] = dashfile.Project{Name: p.Name, Members: ms}
	}
	return f
}

func TestStore_RefusesAtInsertWhatTheDashboardFileRefuses(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	at := func(c byte, n int) string { return strings.Repeat(string(c), n) }
	bad := map[string]string{"empty": "", "256 bytes": at('a', 256), "control": "a\x1fb", "DEL": "a\x7fb", "not ASCII": "é", "tab": "a\tb"}
	for name, p := range bad {
		wantErr(t, s.AddMember(ctx, Member{Ref: r, Issuer: p, Subject: "s", Role: "owner"}), ErrConflict)
		wantErr(t, s.AddMember(ctx, Member{Ref: r, Issuer: "i", Subject: p, Role: "owner"}), ErrConflict)
		wantErr(t, s.Revoke(ctx, p, "s", time.Now()), ErrConflict)
		if err := s.Revoke(ctx, "i", p, time.Now()); !errors.Is(err, ErrConflict) {
			t.Fatalf("revocation of subject %s: %v", name, err)
		}
		d := memberIssuer()
		d.Issuer = p
		wantErr(t, s.SetDashboardIssuer(ctx, d), ErrConflict)
	}
	for _, role := range []string{"", "admin", "Owner", "read-only"} {
		wantErr(t, s.AddMember(ctx, Member{Ref: r, Issuer: "i", Subject: "s", Role: role}), ErrConflict)
	}
	key := func(kid, kty, n, e string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"keys":[{"kid":%q,"kty":%q,"n":%q,"e":%q}]}`, kid, kty, n, e))
	}
	n := memberTestN()
	for name, edit := range map[string]func(d *DashboardIssuer){
		"17 keys":                  func(d *DashboardIssuer) { d.JWKS = memberJWKS(dashfile.MaxKeys+1, "k") },
		"kty EC":                   func(d *DashboardIssuer) { d.JWKS = key("k", "EC", n, "AQAB") },
		"empty kid":                func(d *DashboardIssuer) { d.JWKS = key("", "RSA", n, "AQAB") },
		"long kid":                 func(d *DashboardIssuer) { d.JWKS = key(at('k', dashfile.MaxKidBytes+1), "RSA", n, "AQAB") },
		"empty n":                  func(d *DashboardIssuer) { d.JWKS = key("k", "RSA", "", "AQAB") },
		"long n":                   func(d *DashboardIssuer) { d.JWKS = key("k", "RSA", at('A', dashfile.MaxNBytes+1), "AQAB") },
		"empty e":                  func(d *DashboardIssuer) { d.JWKS = key("k", "RSA", n, "") },
		"long e":                   func(d *DashboardIssuer) { d.JWKS = key("k", "RSA", n, at('A', dashfile.MaxEBytes+1)) },
		"a key the loader refuses": func(d *DashboardIssuer) { d.JWKS = key("k", "RSA", "AQAB", "AQAB") },
		"not a key set":            func(d *DashboardIssuer) { d.JWKS = json.RawMessage(`[]`) },
		"empty client_id":          func(d *DashboardIssuer) { d.ClientID = "" },
		"long client_id":           func(d *DashboardIssuer) { d.ClientID = at('c', dashfile.MaxClientIDBytes+1) },
		"empty authorize_url":      func(d *DashboardIssuer) { d.AuthorizeURL = "" },
		"long authorize_url":       func(d *DashboardIssuer) { d.AuthorizeURL = at('a', dashfile.MaxURLBytes+1) },
		"long end_session_url":     func(d *DashboardIssuer) { d.EndSessionURL = at('e', dashfile.MaxURLBytes+1) },
		"session 299 s":            func(d *DashboardIssuer) { d.SessionSeconds = 299 },
		"session above 8 h":        func(d *DashboardIssuer) { d.SessionSeconds = MaxSessionSeconds + 1 },
	} {
		d := memberIssuer()
		edit(&d)
		if err := s.SetDashboardIssuer(ctx, d); !errors.Is(err, ErrConflict) {
			t.Errorf("issuer with %s: %v", name, err)
		}
	}
	if _, err := s.GetDashboardIssuer(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused issuer was stored: %v", err)
	}
	// What the store accepts at every edge: each string at its cap in the
	// byte the encoder writes longest, and at one byte.
	d := DashboardIssuer{Issuer: at('<', 255), ClientID: at('<', dashfile.MaxClientIDBytes), AuthorizeURL: at('&', dashfile.MaxURLBytes),
		EndSessionURL: at('>', dashfile.MaxURLBytes), SessionSeconds: 300,
		JWKS: json.RawMessage(fmt.Sprintf(`{"keys":[{"kid":%q,"kty":"RSA","n":%q,"e":"AQAB"}]}`, at('<', dashfile.MaxKidBytes), n))}
	must(t, s.SetDashboardIssuer(ctx, d))
	for i, p := range []string{at('<', 255), "x", " ", "~", at('"', 255)} {
		must(t, s.AddMember(ctx, Member{Ref: r, Issuer: p, Subject: at('<', 254) + fmt.Sprint(i), Role: "read_only"}))
		must(t, s.Revoke(ctx, p, at('&', 255), time.Now()))
	}
	tbl, err := s.DashboardTable(ctx)
	must(t, err)
	if len(tbl.Projects) != 1 || len(tbl.Projects[0].Members) != 5 || len(tbl.Revoked) != 5 || tbl.Issuer == nil {
		t.Fatalf("table %+v", tbl)
	}
	b, err := memberFile(tbl).Marshal()
	if err != nil {
		t.Fatalf("a table of what the store accepted does not marshal: %v", err)
	}
	if _, err := dashfile.Parse(b); err != nil {
		t.Fatalf("does not parse: %v", err)
	}
}

func TestMaxSessionSeconds_IsTheDashboardFilesBound(t *testing.T) {
	if MaxSessionSeconds != 28800 {
		t.Fatalf("MaxSessionSeconds %d", MaxSessionSeconds)
	}
	f := dashfile.File{Generation: 1, Node: "local", StudioDomain: "studio.test", Studio: "http://10.212.0.3:3000",
		Issuer: &dashfile.Issuer{Iss: "i", ClientID: "c", AuthorizeURL: "a", SessionSeconds: MaxSessionSeconds}}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dashfile.Parse(b); err != nil {
		t.Fatalf("a file with the store's longest session: %v", err)
	}
	f.Issuer.SessionSeconds++
	if _, err := f.Marshal(); err == nil {
		t.Fatal("control: a session longer than the bound was written")
	}
}

func TestAddMember_StatesAndDuplicates(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	other := newActive(t, s, 2)
	memberAdd(t, s, r, "user-2", "developer")
	memberAdd(t, s, r, "user-1", "owner")
	wantErr(t, s.AddMember(ctx, Member{Ref: r, Issuer: "https://issuer.test", Subject: "user-1", Role: "read_only"}), ErrConflict)
	memberAdd(t, s, other, "user-1", "read_only") // the same principal in another project
	wantErr(t, s.AddMember(ctx, Member{Ref: ref(99), Issuer: "i", Subject: "s", Role: "owner"}), ErrNotFound)
	ms, err := s.ListMembers(ctx, r)
	must(t, err)
	if len(ms) != 2 || ms[0].Subject != "user-1" || ms[0].Role != "owner" || ms[1].Subject != "user-2" || ms[0].Ref != r ||
		ms[0].AddedAt.IsZero() || time.Since(ms[0].AddedAt) > time.Hour {
		t.Fatalf("members %+v", ms)
	}
	if _, err := s.ListMembers(ctx, ref(99)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("members of no project: %v", err)
	}
	for i, state := range []string{"provisioning", "active", "restarting", "restoring", "deleting", "deleted", "purged", "aborted"} {
		r := ref(10 + i)
		mustCreate(t, s, r)
		sqlExec(t, s, "update project set state = $2 where ref = $1", r, state)
		err := s.AddMember(ctx, Member{Ref: r, Issuer: "i", Subject: "s", Role: "owner"})
		switch state {
		case "active", "restarting", "restoring":
			must(t, err)
		default:
			if !errors.Is(err, ErrConflict) {
				t.Errorf("%s: %v", state, err)
			}
		}
	}
}

// memberFill gives r n members by statement.
func memberFill(t *testing.T, s *Store, r string, n int) {
	t.Helper()
	sqlExec(t, s, "insert into member (ref, issuer, subject, role) select $1, 'fill', 's' || g, 'owner' from generate_series(1, $2) g", r, n)
}

// memberRace runs AddMember for each (ref, subject) at once and counts the
// successes; every failure must be ErrConflict.
func memberRace(t *testing.T, s *Store, adds [][2]string) (ok int) {
	t.Helper()
	errs := race(len(adds), func(i int) error {
		return s.AddMember(context.Background(), Member{Ref: adds[i][0], Issuer: "i", Subject: adds[i][1], Role: "owner"})
	})
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrConflict):
			t.Fatal(err)
		}
	}
	return ok
}

func TestAddMember_CapRefused(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	memberFill(t, s, r, dashfile.MaxMembers)
	err := s.AddMember(ctx, Member{Ref: r, Issuer: "i", Subject: "s", Role: "owner"})
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "the project has the most members") {
		t.Fatalf("the 257th member: %v", err)
	}
	for round := range 5 {
		sqlExec(t, s, "delete from member where ref = $1 and (issuer, subject) in (select issuer, subject from member where ref = $1 limit 1)", r)
		if ok := memberRace(t, s, [][2]string{{r, fmt.Sprint("a", round)}, {r, fmt.Sprint("b", round)}}); ok != 1 {
			t.Fatalf("round %d: %d adds at 255 succeeded", round, ok)
		}
		if n := count(t, s, "select count(*) from member where ref = $1", r); n != dashfile.MaxMembers {
			t.Fatalf("round %d: %d members", round, n)
		}
	}
}

func TestAddMember_NodeWideCapRefused(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	full := dashfile.MaxMemberRows / dashfile.MaxMembers
	for i := range full {
		memberFill(t, s, newActive(t, s, i+1), dashfile.MaxMembers)
	}
	a, b := newActive(t, s, 100), newActive(t, s, 101)
	err := s.AddMember(ctx, Member{Ref: a, Issuer: "i", Subject: "s", Role: "owner"})
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "the node has the most members") {
		t.Fatalf("the 16,385th member row: %v", err)
	}
	// Rows of a project the file no longer carries for good are not counted.
	gone := newActive(t, s, 102)
	sqlExec(t, s, "delete from member where ref = $1 and subject = 's1'", ref(1))
	memberAdd(t, s, gone, "user-1", "owner")
	sqlExec(t, s, "update project set state = 'purged' where ref = $1", gone)
	for round := range 5 {
		if round > 0 {
			sqlExec(t, s, "delete from member where ref = $1 and (issuer, subject) in (select issuer, subject from member where ref = $1 limit 1)", ref(1+round))
		}
		if ok := memberRace(t, s, [][2]string{{a, fmt.Sprint("a", round)}, {b, fmt.Sprint("b", round)}}); ok != 1 {
			t.Fatalf("round %d: %d adds at 16,383 succeeded", round, ok)
		}
	}
	if n := count(t, s, "select count(*) from member where ref <> $1", gone); n != dashfile.MaxMemberRows {
		t.Fatalf("%d member rows", n)
	}
}

func TestChangeMember_FromRoleGuard(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	memberAdd(t, s, r, "user-1", "developer")
	wantErr(t, memberChange(s, r, "user-1", "owner", "read_only"), ErrConflict)
	if role, _ := s.MemberRole(ctx, r, "https://issuer.test", "user-1"); role != "developer" {
		t.Fatalf("role %q after a refused change", role)
	}
	wantErr(t, memberChange(s, r, "user-1", "developer", "admin"), ErrConflict)
	wantErr(t, memberChange(s, r, "user-9", "developer", "owner"), ErrNotFound)
	must(t, memberChange(s, r, "user-1", "developer", "owner"))
	if role, _ := s.MemberRole(ctx, r, "https://issuer.test", "user-1"); role != "owner" {
		t.Fatalf("role %q", role)
	}
	must(t, memberChange(s, r, "user-1", "owner", ""))
	wantErr(t, memberChange(s, r, "user-1", "owner", ""), ErrNotFound)
}

func TestMemberRole(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	memberAdd(t, s, r, "user-1", "read_only")
	if role, err := s.MemberRole(ctx, r, "https://issuer.test", "user-1"); err != nil || role != "read_only" {
		t.Fatalf("%q %v", role, err)
	}
	if _, err := s.MemberRole(ctx, r, "https://other.test", "user-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another issuer: %v", err)
	}
	sqlExec(t, s, "update project set state = 'deleted' where ref = $1", r)
	if role, err := s.MemberRole(ctx, r, "https://issuer.test", "user-1"); err != nil || role != "read_only" {
		t.Fatalf("a deleted project's member: %q %v", role, err)
	}
}

func TestChangeMember_ReadOnlyEnds_WritesTheCleanupRow(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	const delay = 10 * time.Minute
	memberSetDelay(t, s, delay)
	r := newActive(t, s, 1)
	for i := range 12 {
		memberAdd(t, s, r, fmt.Sprint("ro-", i), "read_only")
	}
	memberAdd(t, s, r, "dev", "developer")

	// A removal of a developer and a change to read_only write none.
	must(t, memberChange(s, r, "dev", "developer", "read_only"))
	must(t, memberChange(s, r, "dev", "read_only", "read_only"))
	memberAdd(t, s, r, "dev2", "developer")
	must(t, memberChange(s, r, "dev2", "developer", ""))
	if _, ok := memberCleanupRow(t, s, r); ok {
		t.Fatal("a change that ends no read_only membership wrote the record")
	}
	// A failed change writes none: a guard refusal, and a transaction that
	// fails after the change.
	wantErr(t, memberChange(s, r, "ro-0", "developer", ""), ErrConflict)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := changeMemberTx(ctx, tx, r, "https://issuer.test", "ro-0", "read_only", ""); err != nil {
			return err
		}
		if n := 0; tx.QueryRow(ctx, "select count(*) from readonly_cleanup where ref = $1", r).Scan(&n) != nil || n != 1 {
			return fmt.Errorf("no record inside the change's transaction")
		}
		return errors.New("later step failed")
	})
	if err == nil || err.Error() != "later step failed" {
		t.Fatal(err)
	}
	if _, ok := memberCleanupRow(t, s, r); ok {
		t.Fatal("a rolled-back change left the record")
	}
	if role, _ := s.MemberRole(ctx, r, "https://issuer.test", "ro-0"); role != "read_only" {
		t.Fatal("the rolled-back removal took effect")
	}

	// A removal: due is the database's now plus the delay.
	must(t, memberChange(s, r, "ro-0", "read_only", ""))
	now := memberDBNow(t, s)
	row, ok := memberCleanupRow(t, s, r)
	if !ok || row.DueFixed || row.Failures != 0 {
		t.Fatalf("record %+v %v", row, ok)
	}
	memberNear(t, "due", row.Due, now.Add(delay), 30*time.Second)
	memberNear(t, "next_try", row.NextTry, now, 30*time.Second)

	// A second one keeps the later due and resets the rest.
	sqlExec(t, s, "update readonly_cleanup set due = now() + interval '1 day', due_fixed = true, failures = 3, next_try = now() + interval '1 hour' where ref = $1", r)
	must(t, memberChange(s, r, "ro-1", "read_only", "developer"))
	now = memberDBNow(t, s)
	row, _ = memberCleanupRow(t, s, r)
	if row.DueFixed || row.Failures != 0 {
		t.Fatalf("record not reset: %+v", row)
	}
	memberNear(t, "kept due", row.Due, now.Add(24*time.Hour), 30*time.Second)
	memberNear(t, "next_try", row.NextTry, now, 30*time.Second)
	// An earlier stored due is moved to the later one.
	sqlExec(t, s, "update readonly_cleanup set due = now() - interval '1 day' where ref = $1", r)
	must(t, memberChange(s, r, "ro-2", "read_only", "owner"))
	row, _ = memberCleanupRow(t, s, r)
	memberNear(t, "moved due", row.Due, memberDBNow(t, s).Add(delay), 30*time.Second)

	// A project that loses ten read-only members has one record.
	for i := 3; i < 12; i++ {
		must(t, memberChange(s, r, fmt.Sprint("ro-", i), "read_only", ""))
	}
	if n := count(t, s, "select count(*) from readonly_cleanup"); n != 1 {
		t.Fatalf("%d records", n)
	}
}

func TestReadOnlyCleanups_ActiveOnly_DoneOnlyAfterDue(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	rs := make([]string, 6)
	for i := range rs {
		rs[i] = newActive(t, s, i+1)
		memberAdd(t, s, rs[i], "ro", "read_only")
		must(t, memberChange(s, rs[i], "ro", "read_only", ""))
	}
	// next_try: 0 three minutes ago, 1 five minutes ago, 2 one minute ago, 3
	// in the future; 4 is due but its project is restarting, 5 deleted.
	for i, ago := range []string{"3 minutes", "5 minutes", "1 minute", "-1 hour", "10 minutes", "10 minutes"} {
		sqlExec(t, s, "update readonly_cleanup set next_try = now() - $2::interval where ref = $1", rs[i], ago)
	}
	sqlExec(t, s, "update project set state = 'restarting' where ref = $1", rs[4])
	sqlExec(t, s, "update project set state = 'deleted' where ref = $1", rs[5])
	rows, now, err := s.ReadOnlyCleanups(ctx, 2)
	must(t, err)
	memberNear(t, "now", now, memberDBNow(t, s), 30*time.Second)
	if len(rows) != 2 || rows[0].Ref != rs[1] || rows[1].Ref != rs[0] {
		t.Fatalf("rows %+v", rows)
	}
	rows, _, err = s.ReadOnlyCleanups(ctx, 10)
	must(t, err)
	if len(rows) != 3 || rows[2].Ref != rs[2] {
		t.Fatalf("rows %+v", rows)
	}
	if n := count(t, s, "select count(*) from readonly_cleanup"); n != 6 {
		t.Fatalf("listing removed rows: %d left", n)
	}

	// Done: a fixed row whose due is not after the start is removed.
	start := memberDBNow(t, s)
	sqlExec(t, s, "update readonly_cleanup set due = $2, due_fixed = true where ref = $1", rs[0], start)
	must(t, s.DoneReadOnlyCleanup(ctx, rs[0], start))
	if _, ok := memberCleanupRow(t, s, rs[0]); ok {
		t.Fatal("a fixed row due at the run's start stayed")
	}
	// A fixed row due after the start stays: failures zero, next attempt at due.
	sqlExec(t, s, "update readonly_cleanup set due = $2, due_fixed = true, failures = 2 where ref = $1", rs[1], start.Add(time.Microsecond))
	must(t, s.DoneReadOnlyCleanup(ctx, rs[1], start))
	if row, ok := memberCleanupRow(t, s, rs[1]); !ok || row.Failures != 0 || !row.NextTry.Equal(row.Due) {
		t.Fatalf("row %+v %v", row, ok)
	}
	// A row not fixed stays with failures zero and the next attempt it had.
	nextTry := start.Add(-time.Minute)
	sqlExec(t, s, "update readonly_cleanup set due = $2, due_fixed = false, failures = 2, next_try = $3 where ref = $1", rs[2], start.Add(time.Hour), nextTry)
	must(t, s.DoneReadOnlyCleanup(ctx, rs[2], start))
	if row, ok := memberCleanupRow(t, s, rs[2]); !ok || row.Failures != 0 || !row.NextTry.Equal(nextTry) || row.DueFixed {
		t.Fatalf("row not fixed after a success %+v %v", row, ok)
	}
	// A run that started before a later membership change does not remove
	// the row that change wrote.
	sqlExec(t, s, "update readonly_cleanup set due = $2, due_fixed = true where ref = $1", rs[3], start.Add(-time.Hour))
	memberAdd(t, s, rs[3], "ro2", "read_only")
	must(t, memberChange(s, rs[3], "ro2", "read_only", ""))
	must(t, s.DoneReadOnlyCleanup(ctx, rs[3], start))
	row, ok := memberCleanupRow(t, s, rs[3])
	if !ok {
		t.Fatal("a row a later change wrote was removed")
	}
	// That change's first run is not pushed back to its due.
	if row.DueFixed || row.NextTry.After(memberDBNow(t, s)) {
		t.Fatalf("the later change's first run was postponed: %+v", row)
	}
	must(t, s.DoneReadOnlyCleanup(ctx, ref(99), start)) // no row: nothing to do
}

func TestFixReadOnlyCleanupDue_Once(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	const delay = 10 * time.Minute
	memberSetDelay(t, s, delay)
	r := newActive(t, s, 1)
	memberAdd(t, s, r, "ro", "read_only")
	memberAdd(t, s, r, "ro2", "read_only")
	must(t, memberChange(s, r, "ro", "read_only", ""))
	first, _ := memberCleanupRow(t, s, r)
	gen := memberDBNow(t, s).Add(time.Hour).UnixMilli()
	must(t, s.FixReadOnlyCleanupDue(ctx, r, gen, first.Due))
	row, _ := memberCleanupRow(t, s, r)
	if !row.DueFixed || !row.Due.Equal(time.UnixMilli(gen).Add(delay)) {
		t.Fatalf("after the fix %+v, want due %v", row, time.UnixMilli(gen).Add(delay))
	}
	must(t, s.FixReadOnlyCleanupDue(ctx, r, gen+int64(time.Hour/time.Millisecond), row.Due))
	if again, _ := memberCleanupRow(t, s, r); again != row {
		t.Fatalf("a second fix moved the record: %+v", again)
	}
	// The later of due and the generation: an earlier generation keeps due.
	must(t, memberChange(s, r, "ro2", "read_only", ""))
	moved, _ := memberCleanupRow(t, s, r)
	if moved.DueFixed {
		t.Fatal("a membership change kept the mark")
	}
	must(t, s.FixReadOnlyCleanupDue(ctx, r, first.Due.Add(-24*time.Hour).UnixMilli(), moved.Due))
	if row, _ := memberCleanupRow(t, s, r); !row.DueFixed || !row.Due.Equal(moved.Due) {
		t.Fatalf("an earlier generation: %+v, due was %v", row, moved.Due)
	}
	must(t, s.FixReadOnlyCleanupDue(ctx, ref(99), gen, first.Due))
}

// A change committed between the converger's read of a record and its fix:
// the fix names the due it read, finds another, and leaves the record
// unfixed for the next round, which fixes it from the file that carries the
// later change.
func TestFixReadOnlyCleanupDue_LaterChangeLeftUnfixed(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	memberSetDelay(t, s, 10*time.Minute)
	r := newActive(t, s, 1)
	memberAdd(t, s, r, "ro", "read_only")
	memberAdd(t, s, r, "ro2", "read_only")
	must(t, memberChange(s, r, "ro", "read_only", ""))
	seen, _ := memberCleanupRow(t, s, r)
	gen := memberDBNow(t, s).UnixMilli()
	// The second change, committed after the read, moves due.
	sqlExec(t, s, "update readonly_cleanup set due = due - interval '1 second' where ref = $1", r)
	must(t, memberChange(s, r, "ro2", "read_only", ""))
	later, _ := memberCleanupRow(t, s, r)
	if later.Due.Equal(seen.Due) {
		t.Fatal("fixture: the second change did not move due")
	}
	must(t, s.FixReadOnlyCleanupDue(ctx, r, gen, seen.Due))
	if row, _ := memberCleanupRow(t, s, r); row.DueFixed || !row.Due.Equal(later.Due) {
		t.Fatalf("a record moved after it was read was fixed: %+v", row)
	}
	// Control: with the due it now holds, it is fixed.
	must(t, s.FixReadOnlyCleanupDue(ctx, r, gen, later.Due))
	if row, _ := memberCleanupRow(t, s, r); !row.DueFixed {
		t.Fatalf("control: not fixed %+v", row)
	}
}

func TestFailReadOnlyCleanup_BacksOffToAnHour(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	for _, sub := range []string{"ro", "ro2"} {
		memberAdd(t, s, r, sub, "read_only")
	}
	must(t, memberChange(s, r, "ro", "read_only", ""))
	for i, want := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60} {
		must(t, s.FailReadOnlyCleanup(ctx, r, time.Minute))
		row, _ := memberCleanupRow(t, s, r)
		if row.Failures != i+1 {
			t.Fatalf("failures %d after %d", row.Failures, i+1)
		}
		memberNear(t, fmt.Sprint("next_try after failure ", i+1), row.NextTry, memberDBNow(t, s).Add(want*time.Minute), 30*time.Second)
	}
	sqlExec(t, s, "update readonly_cleanup set failures = 1000 where ref = $1", r)
	must(t, s.FailReadOnlyCleanup(ctx, r, time.Minute))
	row, _ := memberCleanupRow(t, s, r)
	memberNear(t, "next_try after 1001 failures", row.NextTry, memberDBNow(t, s).Add(time.Hour), 30*time.Second)
	// A success sets the count to zero; so does a membership change.
	must(t, s.DoneReadOnlyCleanup(ctx, r, memberDBNow(t, s)))
	if row, _ := memberCleanupRow(t, s, r); row.Failures != 0 {
		t.Fatalf("failures %d after a success", row.Failures)
	}
	must(t, s.FailReadOnlyCleanup(ctx, r, time.Minute))
	must(t, memberChange(s, r, "ro2", "read_only", ""))
	if row, _ := memberCleanupRow(t, s, r); row.Failures != 0 {
		t.Fatalf("failures %d after a membership change", row.Failures)
	}
}

func TestRevoke_KeepsTheLaterTime(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	stored := func() time.Time {
		var nb time.Time
		must(t, s.pool.QueryRow(ctx, "select not_before from principal_revocation where issuer = 'i' and subject = 's'").Scan(&nb))
		return nb
	}
	t1 := time.Now().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	must(t, s.Revoke(ctx, "i", "s", t1))
	if got := stored(); !got.Equal(t1.Truncate(time.Microsecond)) {
		t.Fatalf("stored %v, want %v to the microsecond", got, t1)
	}
	must(t, s.Revoke(ctx, "i", "s", t1.Add(-time.Minute)))
	if got := stored(); !got.Equal(t1.Truncate(time.Microsecond)) {
		t.Fatalf("an earlier revocation moved it to %v", got)
	}
	must(t, s.Revoke(ctx, "i", "s", t1.Add(time.Minute)))
	if got := stored(); !got.Equal(t1.Add(time.Minute).Truncate(time.Microsecond)) {
		t.Fatalf("a later revocation left %v", got)
	}
}

func TestRevoke_PrunesAndCaps(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	sqlExec(t, s, "insert into principal_revocation values ('old', 's', now() - interval '28801 seconds'), ('young', 's', now() - interval '28740 seconds')")
	must(t, s.Revoke(ctx, "i", "s", time.Now()))
	if n := count(t, s, "select count(*) from principal_revocation where issuer = 'old'"); n != 0 {
		t.Fatal("a revocation older than the session lifetime stayed")
	}
	if n := count(t, s, "select count(*) from principal_revocation where issuer = 'young'"); n != 1 {
		t.Fatal("a revocation younger than the session lifetime was removed")
	}
	sqlExec(t, s, "delete from principal_revocation")
	sqlExec(t, s, "insert into principal_revocation select 'i', 's' || g, now() from generate_series(1, $1) g", dashfile.MaxRevocations)
	err := s.Revoke(ctx, "i", "new", time.Now())
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("the 4,097th live revocation: %v", err)
	}
	must(t, s.Revoke(ctx, "i", "s1", time.Now())) // a principal already revoked: an update
	sqlExec(t, s, "update principal_revocation set not_before = now() - interval '28801 seconds' where subject = 's2'")
	must(t, s.Revoke(ctx, "i", "new", time.Now())) // the aged one is pruned first
	if n := count(t, s, "select count(*) from principal_revocation"); n != dashfile.MaxRevocations {
		t.Fatalf("%d revocations", n)
	}
	// Two revocations at the last place: one is taken.
	for round := range 5 {
		sqlExec(t, s, "delete from principal_revocation where subject = $1", fmt.Sprint("s", 10+round))
		errs := race(2, func(i int) error { return s.Revoke(ctx, "i", fmt.Sprint("race-", round, "-", i), time.Now()) })
		if (errs[0] == nil) == (errs[1] == nil) || !errors.Is(errors.Join(errs...), ErrConflict) {
			t.Fatalf("round %d: %v", round, errs)
		}
	}
}

func TestDashboardIssuer_SetGet_KeyCap(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	if _, err := s.GetDashboardIssuer(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unset issuer: %v", err)
	}
	d := memberIssuer()
	d.EndSessionURL = "https://issuer.test/logout"
	d.JWKS = memberJWKS(dashfile.MaxKeys, "k")
	must(t, s.SetDashboardIssuer(ctx, d))
	got, err := s.GetDashboardIssuer(ctx)
	must(t, err)
	var a, b any
	_ = json.Unmarshal(got.JWKS, &a)
	_ = json.Unmarshal(d.JWKS, &b)
	if got.Issuer != d.Issuer || got.ClientID != d.ClientID || got.AuthorizeURL != d.AuthorizeURL ||
		got.EndSessionURL != d.EndSessionURL || got.SessionSeconds != d.SessionSeconds || fmt.Sprint(a) != fmt.Sprint(b) || got.UpdatedAt.IsZero() {
		t.Fatalf("got %+v", got)
	}
	d2 := d
	d2.JWKS = memberJWKS(dashfile.MaxKeys+1, "x")
	wantErr(t, s.SetDashboardIssuer(ctx, d2), ErrConflict)
	if again, _ := s.GetDashboardIssuer(ctx); !strings.Contains(string(again.JWKS), `"k15"`) || strings.Contains(string(again.JWKS), `"x0"`) {
		t.Fatal("a refused key set replaced the stored one")
	}
	d2.JWKS, d2.ClientID = memberJWKS(1, "y"), "other"
	must(t, s.SetDashboardIssuer(ctx, d2))
	if again, _ := s.GetDashboardIssuer(ctx); again.ClientID != "other" || !strings.Contains(string(again.JWKS), `"y0"`) || again.UpdatedAt.Before(got.UpdatedAt) {
		t.Fatalf("replaced issuer %+v", again)
	}
	if n := count(t, s, "select count(*) from dashboard_issuer"); n != 1 {
		t.Fatalf("%d issuer rows", n)
	}
}

func TestDashboardTable_OnlyLiveProjects_OneSnapshot(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	tbl, err := s.DashboardTable(ctx)
	must(t, err)
	if tbl.Issuer != nil || len(tbl.Projects) != 0 || len(tbl.Revoked) != 0 {
		t.Fatalf("empty store: %+v", tbl)
	}
	states := []string{"provisioning", "active", "restarting", "restoring", "deleting", "deleted", "purged", "aborted"}
	for i, state := range states {
		r := ref(len(states) - i) // refs in the reverse order of creation
		mustCreate(t, s, r)
		sqlExec(t, s, "update project set state = $2, name = $3 where ref = $1", r, state, "n-"+state)
		sqlExec(t, s, "insert into member (ref, issuer, subject, role) values ($1, 'i', 'b', 'owner'), ($1, 'i', 'a', 'read_only')", r)
	}
	must(t, s.SetDashboardIssuer(ctx, memberIssuer()))
	must(t, s.Revoke(ctx, "i", "x", time.Now()))
	tbl, err = s.DashboardTable(ctx)
	must(t, err)
	var got []string
	for _, p := range tbl.Projects {
		if len(p.Members) != 2 || p.Members[0].Subject != "a" || p.Members[1].Role != "owner" || p.Members[0].Ref != p.Ref {
			t.Fatalf("members of %s: %+v", p.Ref, p.Members)
		}
		got = append(got, p.Ref+" "+p.Name)
	}
	if want := []string{ref(5) + " n-restoring", ref(6) + " n-restarting", ref(7) + " n-active"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("projects %v, want %v", got, want)
	}
	if tbl.Issuer == nil || tbl.Issuer.ClientID != "supapace" || len(tbl.Revoked) != 1 {
		t.Fatalf("table %+v", tbl)
	}

	// One snapshot: a member committed while the read is under way, after its
	// first statement, is not in the table.
	lock, err := s.pool.Begin(ctx)
	must(t, err)
	defer lock.Rollback(ctx)
	_, err = lock.Exec(ctx, "lock table member in access exclusive mode")
	must(t, err)
	type result struct {
		tbl DashboardTable
		err error
	}
	done := make(chan result, 1)
	go func() {
		tbl, err := s.DashboardTable(ctx)
		done <- result{tbl, err}
	}()
	for deadline := time.Now().Add(time.Minute); ; {
		if count(t, s, "select count(*) from pg_locks where relation = 'member'::regclass and not granted") == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the table's read never waited on the member table")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, err = lock.Exec(ctx, "insert into member (ref, issuer, subject, role) values ($1, 'i', 'late', 'owner')", ref(7))
	must(t, err)
	must(t, lock.Commit(ctx))
	res := <-done
	must(t, res.err)
	for _, p := range res.tbl.Projects {
		if p.Ref == ref(7) && len(p.Members) != 2 {
			t.Fatalf("a member committed after the read began is in the table: %+v", p.Members)
		}
	}
	tbl, err = s.DashboardTable(ctx)
	must(t, err)
	if len(tbl.Projects[2].Members) != 3 {
		t.Fatalf("control: the next read lacks the member: %+v", tbl.Projects[2])
	}
}

func TestDashboardTable_OldRevocationsLeftOut(t *testing.T) {
	s := newStore(t, testConfig())
	sqlExec(t, s, `insert into principal_revocation values
		('i', 'aged', now() - interval '8 hours 1 second'), ('i', 'young', now() - interval '7 hours 59 minutes')`)
	tbl, err := s.DashboardTable(context.Background())
	must(t, err)
	if len(tbl.Revoked) != 1 || tbl.Revoked[0].Subject != "young" || tbl.Revoked[0].Issuer != "i" {
		t.Fatalf("revocations %+v", tbl.Revoked)
	}
	if d := time.Since(tbl.Revoked[0].NotBefore); d < 7*time.Hour || d > 8*time.Hour {
		t.Fatalf("not_before %v", tbl.Revoked[0].NotBefore)
	}
}
