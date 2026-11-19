package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
)

// reply is a scripted server's answer to one statement: an error with the
// SQLSTATE code (and the message msg), or rows of the column types oids (text
// values). With stall set the answer is held back until the channel is closed.
type reply struct {
	code  string
	msg   string // the error's message; empty: "t-refused"
	oids  []uint32
	rows  [][]string
	stall <-chan struct{}
}

// scriptedConn returns a client connection to an in-process server that
// records every statement and answers it as script says; run is false when
// the statement is only described.
func scriptedConn(t *testing.T, script func(sql string, run bool) reply) (*pgx.Conn, *recorder) {
	t.Helper()
	cli, srv := net.Pipe()
	rec := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer srv.Close()
		serveScripted(srv, rec, script)
	}()
	cfg, err := pgx.ParseConfig("postgres://t@127.0.0.1:5432/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.DialFunc = func(context.Context, string, string) (net.Conn, error) { return cli, nil }
	cfg.LookupFunc = func(_ context.Context, h string) ([]string, error) { return []string{h}, nil }
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()); cli.Close(); <-done })
	return conn, rec
}

func serveScripted(srv net.Conn, rec *recorder, script func(string, bool) reply) {
	be := pgproto3.NewBackend(srv, srv)
	for {
		m, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		if _, ok := m.(*pgproto3.StartupMessage); ok {
			break
		}
		srv.Write([]byte("N"))
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.6"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if be.Flush() != nil {
		return
	}
	desc := func(oids []uint32) pgproto3.BackendMessage {
		if len(oids) == 0 {
			return &pgproto3.NoData{}
		}
		rd := &pgproto3.RowDescription{}
		for i, o := range oids {
			rd.Fields = append(rd.Fields, pgproto3.FieldDescription{Name: []byte("c" + strconv.Itoa(i)), DataTypeOID: o, DataTypeSize: -1, TypeModifier: -1})
		}
		return rd
	}
	// run answers one statement; it reports false after an error.
	run := func(sql string, formats []int16, simple bool) bool {
		r := script(sql, true)
		if r.stall != nil {
			<-r.stall
		}
		if r.code != "" {
			msg := r.msg
			if msg == "" {
				msg = "t-refused"
			}
			be.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: r.code, Message: msg, Detail: "t-detail", Hint: "t-hint",
				InternalQuery: "t-internal", Where: "t-where"})
			return false
		}
		if len(r.oids) == 0 {
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("OK")})
			return true
		}
		if simple {
			be.Send(desc(r.oids))
		}
		for _, row := range r.rows {
			dr := &pgproto3.DataRow{}
			for i, v := range row {
				b := []byte(v)
				if (len(formats) == 1 && formats[0] == 1 || i < len(formats) && formats[i] == 1) && r.oids[i] == 16 {
					b = []byte{map[string]byte{"t": 1}[v]}
				}
				dr.Values = append(dr.Values, b)
			}
			be.Send(dr)
		}
		be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT " + strconv.Itoa(len(r.rows)))})
		return true
	}
	params := regexp.MustCompile(`\$[0-9]+`)
	prepared := map[string]string{}
	var portal string
	var formats []int16
	failed := false // after an error, until the next Sync
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		rec.mu.Lock()
		rec.kinds = append(rec.kinds, fmt.Sprintf("%T", msg))
		switch m := msg.(type) {
		case *pgproto3.Query:
			rec.sent = append(rec.sent, m.String)
		case *pgproto3.Parse:
			rec.sent = append(rec.sent, m.Query)
		}
		rec.mu.Unlock()
		switch m := msg.(type) {
		case *pgproto3.Query:
			run(m.String, nil, true)
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Sync:
			failed = false
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Terminate:
			return
		default:
			if failed {
				continue
			}
			switch m := msg.(type) {
			case *pgproto3.Parse:
				prepared[m.Name] = m.Query
				be.Send(&pgproto3.ParseComplete{})
			case *pgproto3.Describe:
				q := prepared[m.Name]
				if m.ObjectType == 'P' {
					q = prepared[portal]
				} else {
					pd := &pgproto3.ParameterDescription{}
					for range params.FindAllString(q, -1) {
						pd.ParameterOIDs = append(pd.ParameterOIDs, 25)
					}
					be.Send(pd)
				}
				be.Send(desc(script(q, false).oids))
			case *pgproto3.Bind:
				portal, formats = m.PreparedStatement, slices.Clone(m.ResultFormatCodes)
				be.Send(&pgproto3.BindComplete{})
			case *pgproto3.Execute:
				failed = !run(prepared[portal], formats, false)
			}
		}
		if be.Flush() != nil {
			return
		}
	}
}

// managerSecrets are test secrets with a manager password and its salt, and
// the manager's password statement for them.
func managerSecrets(t *testing.T) (Secrets, string) {
	t.Helper()
	s := testSecrets(t)
	s.PoolerPassword = rnd(32)
	salt, err := pgsock.ScramSalt([]byte(rnd(32)), rnd(10), "supapace_pooler")
	if err != nil {
		t.Fatal(err)
	}
	s.ScramSalts["supapace_pooler"] = salt
	v, err := pgsock.ScramVerifier(s.PoolerPassword, salt)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := verifierStatement(sqlPasswordPooler, v)
	if err != nil {
		t.Fatal(err)
	}
	return s, stmt
}

// asDefined answers the two reads of the manager and its helper as a cluster
// that holds both as defined.
func asDefined(sql string, _ bool) reply {
	switch sql {
	case sqlPoolerRole:
		return reply{oids: []uint32{16, 16, 16, 16, 16, 16, 16, 16, 25}, rows: [][]string{{"f", "f", "f", "f", "f", "t", "t", "t", poolerSchemaACL}}}
	case sqlPoolerHelper:
		return reply{oids: []uint32{25, 16, 16, 16, 25}, rows: [][]string{{"supabase_admin", "t", "t", "t", poolerHelperGrantees}}}
	case sqlRoleExists:
		return reply{oids: []uint32{16}, rows: [][]string{{"t"}}}
	}
	return reply{}
}

// TestEnsurePoolerLogin_StopsAtTheFirstFailedStatement: a statement the server
// refuses ends the call with an error and nothing is sent after it. Only the
// role's creation may answer "it exists", and only with that code.
func TestEnsurePoolerLogin_StopsAtTheFirstFailedStatement(t *testing.T) {
	s, verifier := managerSecrets(t)
	all := []string{sqlCreatePooler, verifier, sqlPoolerSchema, sqlPoolerSchemaOwner, sqlPoolerSchemaRevoke,
		sqlPoolerSchemaGrant, sqlCreatePoolerHelper, sqlPoolerHelperOwner, sqlPoolerHelperRevoke, sqlPoolerHelperGrant,
		sqlPoolerRole, sqlPoolerHelper}
	for i, failing := range all {
		for _, code := range []string{"42501", "42710", "42704"} {
			conn, rec := scriptedConn(t, func(sql string, run bool) reply {
				if sql == failing && run {
					return reply{code: code}
				}
				return asDefined(sql, run)
			})
			err := EnsurePoolerLogin(context.Background(), conn, s)
			got := rec.statements()
			if i == 0 && code == "42710" {
				if err != nil || !slices.Equal(got, all) {
					t.Errorf("an existing role: %v, sent %d statements", err, len(got))
				}
				continue
			}
			var se *pgsock.ServerError
			if !errors.As(err, &se) || se.Code != code {
				t.Errorf("statement %d refused with %s: %v", i, code, err)
			}
			if !slices.Equal(got, all[:i+1]) {
				t.Errorf("statement %d refused with %s: %d statements sent, want %d", i, code, len(got), i+1)
			}
			if err != nil && strings.Contains(err.Error(), s.PoolerPassword) {
				t.Errorf("statement %d: the error holds the password", i)
			}
		}
	}
}

// TestRekey_OnlyAnAbsentManagerRoleIsSkipped: "no such role" on the manager's
// statement is a skip and the re-key goes on; any other refusal of it, and "no
// such role" on one of the three, end the re-key with nothing sent after.
func TestRekey_OnlyAnAbsentManagerRoleIsSkipped(t *testing.T) {
	s, manager := managerSecrets(t)
	var three []string
	for i, p := range []string{sqlPasswordSupabaseAdmin, sqlPasswordPostgres, sqlPasswordAuthenticator} {
		pw := []string{s.SupabaseAdminPassword, s.PostgresPassword, s.AuthenticatorPassword}[i]
		v, _ := pgsock.ScramVerifier(pw, s.ScramSalts[platformLogins[i]])
		st, err := verifierStatement(p, v)
		if err != nil {
			t.Fatal(err)
		}
		three = append(three, st)
	}
	tail := []string{sqlRoleExists, sqlGrantBackupSettings, sqlGrantBackupFuncs}
	for _, tc := range []struct {
		name, failing, code string
		ok                  bool
		sent                []string
	}{
		{"manager absent", manager, "42704", true, append(append(slices.Clone(three), manager), tail...)},
		{"manager refused", manager, "42501", false, append(slices.Clone(three), manager)},
		{"manager, another class 42", manager, "42710", false, append(slices.Clone(three), manager)},
		{"postgres absent", three[1], "42704", false, three[:2]},
	} {
		conn, rec := scriptedConn(t, func(sql string, run bool) reply {
			if sql == tc.failing {
				return reply{code: tc.code}
			}
			return asDefined(sql, run)
		})
		err := Rekey(context.Background(), conn, s)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got := rec.statements(); !slices.Equal(got, tc.sent) {
			t.Errorf("%s: sent %d statements, want %d", tc.name, len(got), len(tc.sent))
		}
	}
}

// TestRunAndRekey_RefuseTheManagersSecretsBeforeAnyStatement: a manager
// password that another platform role has, or one without its salt, is refused
// by Run, Rekey and EnsurePoolerLogin before anything is sent.
func TestRunAndRekey_RefuseTheManagersSecretsBeforeAnyStatement(t *testing.T) {
	for name, bad := range map[string]func(*Secrets){
		"password of supabase_admin": func(s *Secrets) { s.PoolerPassword = s.SupabaseAdminPassword },
		"password of postgres":       func(s *Secrets) { s.PoolerPassword = s.PostgresPassword },
		"password of authenticator":  func(s *Secrets) { s.PoolerPassword = s.AuthenticatorPassword },
		"no salt":                    func(s *Secrets) { delete(s.ScramSalts, "supapace_pooler") },
		"short salt":                 func(s *Secrets) { s.ScramSalts["supapace_pooler"] = []byte("short") },
	} {
		s, _ := managerSecrets(t)
		bad(&s)
		for call, fn := range map[string]func(context.Context, *pgx.Conn, Secrets) error{
			"Run": Run, "Rekey": Rekey, "EnsurePoolerLogin": EnsurePoolerLogin} {
			conn, rec := scriptedConn(t, asDefined)
			if err := fn(context.Background(), conn, s); err == nil || len(rec.statements()) != 0 {
				t.Errorf("%s, %s: %v, sent %d statements", call, name, err, len(rec.statements()))
			}
		}
	}
}

// TestRekeyLogin_FailuresByStep: a refused password statement or a refused
// termination is the call's error and nothing follows it; a refused removal of
// large objects is reported in the result alone, with its cause, is not repeated in the same
// call, and what earlier rounds removed stays counted.
func TestRekeyLogin_FailuresByStep(t *testing.T) {
	const role = "supabase_read_only_user"
	v := newVerifier(t, role)
	stmt, err := verifierStatement(sqlPasswordReadOnly, v)
	if err != nil {
		t.Fatal(err)
	}
	removals := func(rec *recorder) int {
		n := 0
		for _, k := range rec.messageKinds() {
			if k == "*pgproto3.Execute" {
				n++
			}
		}
		return n - 1 // the termination is the first statement run with a result
	}
	for _, tc := range []struct {
		name     string
		failing  string
		failAt   int // the removal round that fails (1-based); 0: the statement failing names
		wantErr  bool
		want     RekeyResult
		removals int
	}{
		{"password refused", stmt, 0, true, RekeyResult{}, -1},
		{"termination refused", sqlTerminateRole, 0, true, RekeyResult{}, 0},
		{"first removal refused", "", 1, false, RekeyResult{Terminated: 2, LargeObjectsLeft: true}, 1},
		{"third removal refused", "", 3, false, RekeyResult{Terminated: 2, LargeObjects: 2 * loBatch, LargeObjectsLeft: true}, 3},
	} {
		round := 0
		conn, rec := scriptedConn(t, func(sql string, run bool) reply {
			switch sql {
			case stmt:
				if tc.failing == stmt {
					return reply{code: "57014"}
				}
			case sqlTerminateRole:
				if run && tc.failing == sql {
					return reply{code: "57014"}
				}
				return reply{oids: []uint32{16}, rows: [][]string{{"t"}, {"t"}, {"f"}}}
			case sqlUnlinkReadOnlyLargeObjects:
				if run {
					if round++; round == tc.failAt {
						return reply{code: "57014"}
					}
				}
				return reply{oids: []uint32{25}, rows: slices.Repeat([][]string{{"1"}}, loBatch)}
			}
			return reply{}
		})
		res, err := RekeyLogin(context.Background(), conn, role, v)
		cause := res.LargeObjectsError
		res.LargeObjectsError = ""
		if (cause != "") != (tc.failAt > 0) || len(cause) > 256 || (cause != "" && !strings.Contains(cause, "57014")) {
			t.Errorf("%s: cause %q", tc.name, cause)
		}
		if strings.Contains(cause, "lo_unlink") {
			t.Errorf("%s: the cause holds the statement", tc.name)
		}
		if (err != nil) != tc.wantErr || res != tc.want {
			t.Errorf("%s: %+v %v, want %+v", tc.name, res, err, tc.want)
		}
		if got := rec.statements(); got[0] != stmt {
			t.Errorf("%s: first statement %q", tc.name, got[0])
		}
		if got := removals(rec); tc.removals >= 0 && got != tc.removals {
			t.Errorf("%s: %d removals run, want %d", tc.name, got, tc.removals)
		}
		if tc.removals < 0 && len(rec.statements()) != 1 {
			t.Errorf("%s: sent %q after the refusal", tc.name, rec.statements()[1:])
		}
		if err != nil && strings.Contains(err.Error(), v) {
			t.Errorf("%s: the error holds the verifier", tc.name)
		}
	}
}

// TestSessionCalls_EndWithTheCallersContext: against a server that does not
// answer, each call ends with the caller's deadline as a budget error.
func TestSessionCalls_EndWithTheCallersContext(t *testing.T) {
	s, _ := managerSecrets(t)
	v := newVerifier(t, "postgres")
	for name, call := range map[string]func(context.Context, *pgx.Conn) error{
		"EnsurePoolerLogin": func(ctx context.Context, c *pgx.Conn) error { return EnsurePoolerLogin(ctx, c, s) },
		"EnsureCanary":      EnsureCanary,
		"WriteCanary":       WriteCanary,
		"RekeyLogin": func(ctx context.Context, c *pgx.Conn) error {
			_, err := RekeyLogin(ctx, c, "postgres", v)
			return err
		},
		"SetReadOnlySignal": func(ctx context.Context, c *pgx.Conn) error { return SetReadOnlySignal(ctx, c, true) },
		"CreateRestorePoint": func(ctx context.Context, c *pgx.Conn) error {
			_, err := CreateRestorePoint(ctx, c, "t-point")
			return err
		},
		"AssertServices": func(ctx context.Context, c *pgx.Conn) error {
			_, err := AssertServices(ctx, c, true)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stall := make(chan struct{})
			conn, _ := scriptedConn(t, func(_ string, run bool) reply {
				if run {
					return reply{stall: stall}
				}
				return reply{}
			})
			t.Cleanup(func() { close(stall) }) // before the connection's own clean-up
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			start := time.Now()
			err := call(ctx, conn)
			if err == nil || !pgsock.IsBudget(err) {
				t.Fatalf("error %v", err)
			}
			if d := time.Since(start); d > 8*time.Second {
				t.Fatalf("the call took %v", d)
			}
		})
	}
}

// TestPoolerReadBack_ServerTextIsBoundedAndClean: names the server answers the
// read-back with reach the error of EnsurePoolerLogin and the findings of
// AssertServices sanitised and capped, however long they are.
func TestPoolerReadBack_ServerTextIsBoundedAndClean(t *testing.T) {
	s, _ := managerSecrets(t)
	long := "t-own\x1b[31m\x00\r\n‮" + strings.Repeat("x", 200_000)
	script := func(sql string, run bool) reply {
		if sql == sqlPoolerHelper {
			return reply{oids: []uint32{25, 16, 16, 16, 25}, rows: [][]string{{long, "t", "t", "t", long}}}
		}
		return asDefined(sql, run)
	}
	clean := func(what, text string) {
		t.Helper()
		if len(text) > 256 || strings.ContainsAny(text, "\x1b\x00\r\n‮") || !strings.Contains(text, "t-own") {
			t.Errorf("%s: %d bytes: %.80q", what, len(text), text)
		}
	}
	conn, _ := scriptedConn(t, script)
	err := EnsurePoolerLogin(context.Background(), conn, s)
	if err == nil {
		t.Fatal("a helper of another owner read back as defined")
	}
	clean("error", err.Error())
	conn, _ = scriptedConn(t, script)
	r, err := AssertServices(context.Background(), conn, true)
	if err != nil || len(r) != 2 {
		t.Fatalf("findings %d, %v", len(r), err)
	}
	for _, f := range r {
		if f.OK || f.Name != "service-logins" {
			t.Errorf("finding %+v", f.Name)
		}
		clean("finding", f.Detail)
	}
	// More rows than one, or none, is a difference, never a pass.
	for _, rows := range [][][]string{nil, {{"supabase_admin", "t", "t", "t", poolerHelperGrantees}, {"supabase_admin", "t", "t", "t", poolerHelperGrantees}}} {
		conn, _ := scriptedConn(t, func(sql string, run bool) reply {
			if sql == sqlPoolerHelper {
				return reply{oids: []uint32{25, 16, 16, 16, 25}, rows: rows}
			}
			return asDefined(sql, run)
		})
		if err := EnsurePoolerLogin(context.Background(), conn, s); err == nil {
			t.Errorf("%d helper rows read back as defined", len(rows))
		}
	}
	// Another setting and an empty list of grantees are differences.
	conn, _ = scriptedConn(t, func(sql string, run bool) reply {
		if sql == sqlPoolerHelper {
			return reply{oids: []uint32{25, 16, 16, 16, 25}, rows: [][]string{{"supabase_admin", "t", "t", "f", ""}}}
		}
		return asDefined(sql, run)
	})
	if err := EnsurePoolerLogin(context.Background(), conn, s); err == nil {
		t.Error("a helper with another setting and no grantee read back as defined")
	}
}

// TestPasswordStatements_Forms: the read-only login's statement has the one
// form of the three platform roles'; the manager's sets every attribute of
// the role each time. Both are admitted by verifierStatement and no other
// spelling of them is.
func TestPasswordStatements_Forms(t *testing.T) {
	if want := "alter role supabase_read_only_user with login connection limit -1 valid until 'infinity' password '"; sqlPasswordReadOnly != want {
		t.Errorf("read-only: %q", sqlPasswordReadOnly)
	}
	if want := "alter role supapace_pooler with login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls " +
		"connection limit -1 valid until 'infinity' password '"; sqlPasswordPooler != want {
		t.Errorf("manager: %q", sqlPasswordPooler)
	}
	// The role is made with no attribute of its own: the password statement
	// that follows sets them all.
	if sqlCreatePooler != "create role supapace_pooler" {
		t.Errorf("creation: %q", sqlCreatePooler)
	}
	v, err := pgsock.ScramVerifier("secret-password", make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{sqlPasswordReadOnly, sqlPasswordPooler} {
		if st, err := verifierStatement(p, v); err != nil || st != p+v+"'" {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"alter role supapace_pooler with login password '", "alter role supapace_pooler password '",
		"alter role supabase_read_only_user password '", strings.Replace(sqlPasswordPooler, "nosuperuser", "superuser", 1),
		strings.Replace(sqlPasswordPooler, "supapace_pooler", "supabase_admin", 1)} {
		if _, err := verifierStatement(p, v); err == nil {
			t.Errorf("prefix %q accepted", p)
		}
	}
}

// TestSessionStatements_NamesCarryTheirSchema: in the statements of the
// manager, the canary and the session calls every relation and every function
// is written with its schema.
func TestSessionStatements_NamesCarryTheirSchema(t *testing.T) {
	keyword := map[string]bool{"coalesce": true, "array": true, "operator": true, "values": true, "check": true,
		"conflict": true, "table": true, "exists": true}
	check := func(stmt string) []string {
		s := regexp.MustCompile(`(?s)\$f\$.*\$f\$`).ReplaceAllString(stmt, "")
		s = regexp.MustCompile(`'(?:[^']|'')*'`).ReplaceAllString(s, "''")
		var bad []string
		for _, m := range regexp.MustCompile(`\b(?:from|join|into|table(?: if not exists)?)\s+([a-z_][a-z0-9_.]*)`).FindAllStringSubmatch(s, -1) {
			if !strings.Contains(m[1], ".") && m[1] != "public" {
				bad = append(bad, "relation "+m[1])
			}
		}
		for _, m := range regexp.MustCompile(`([a-z_][a-z0-9_.]*)\s*\(`).FindAllStringSubmatch(s, -1) {
			if !strings.Contains(m[1], ".") && !keyword[m[1]] {
				bad = append(bad, "function "+m[1])
			}
		}
		return bad
	}
	for name, stmt := range map[string]string{
		"sqlCreatePooler": sqlCreatePooler, "sqlPoolerSchema": sqlPoolerSchema, "sqlPoolerSchemaOwner": sqlPoolerSchemaOwner,
		"sqlPoolerSchemaRevoke": sqlPoolerSchemaRevoke, "sqlPoolerSchemaGrant": sqlPoolerSchemaGrant,
		"sqlCreatePoolerHelper": sqlCreatePoolerHelper, "sqlPoolerHelperOwner": sqlPoolerHelperOwner,
		"sqlPoolerHelperRevoke": sqlPoolerHelperRevoke, "sqlPoolerHelperGrant": sqlPoolerHelperGrant,
		"sqlPoolerRole": sqlPoolerRole, "sqlPoolerHelper": sqlPoolerHelper,
		"sqlCanarySchema": sqlCanarySchema, "sqlCanarySchemaOwner": sqlCanarySchemaOwner, "sqlCanarySchemaRevoke": sqlCanarySchemaRevoke,
		"sqlCanaryTable": sqlCanaryTable, "sqlCanaryTableOwner": sqlCanaryTableOwner, "sqlCanaryWrite": sqlCanaryWrite,
		"sqlCanaryRelation": sqlCanaryRelation, "sqlCanaryDrop": sqlCanaryDrop,
		"sqlTerminateRole": sqlTerminateRole, "sqlUnlinkReadOnlyLargeObjects": sqlUnlinkReadOnlyLargeObjects,
		"sqlReadOnlySignalOn": sqlReadOnlySignalOn, "sqlReadOnlySignalOff": sqlReadOnlySignalOff, "sqlRestorePoint": sqlRestorePoint,
	} {
		if bad := check(stmt); len(bad) > 0 {
			t.Errorf("%s: %v", name, bad)
		}
	}
	for _, bad := range []string{"select now()", "select 1 from pg_roles", "insert into t values (1)",
		"select pg_catalog.count(x) from pg_catalog.pg_class join pg_namespace n on true", "create table if not exists t (id int)"} {
		if len(check(bad)) == 0 {
			t.Errorf("control: %q passes", bad)
		}
	}
	// The removal's batch is the one the loop counts with.
	if !strings.HasSuffix(sqlUnlinkReadOnlyLargeObjects, " limit "+strconv.Itoa(loBatch)) || loRounds != 10 {
		t.Errorf("removal: %q, batch %d, rounds %d", sqlUnlinkReadOnlyLargeObjects, loBatch, loRounds)
	}
	// The termination is by role name and by nothing else.
	if want := "select pg_catalog.pg_terminate_backend(pid) from pg_catalog.pg_stat_activity where usename = $1 and pid <> pg_catalog.pg_backend_pid()"; sqlTerminateRole != want {
		t.Errorf("termination: %q", sqlTerminateRole)
	}
}

// TestRekeyLogin_ReadOnlyLoginGetsLoginLimitAndExpiryBack: on the cluster, the
// read-only login's re-key stores the new verifier and gives the role its
// login right, an unlimited connection limit and no expiry back.
func TestRekeyLogin_ReadOnlyLoginGetsLoginLimitAndExpiryBack(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "alter role supabase_read_only_user nologin connection limit 0 valid until '2000-01-01'")
	v := newVerifier(t, "supabase_read_only_user")
	res, err := RekeyLogin(context.Background(), adm, "supabase_read_only_user", v)
	if err != nil || res != (RekeyResult{}) {
		t.Fatalf("%+v %v", res, err)
	}
	const state = `select rolcanlogin::text || ' ' || rolconnlimit::text || ' ' || rolvaliduntil::text || ' ' || (rolpassword = $1)::text
	  from pg_catalog.pg_authid where rolname = 'supabase_read_only_user'`
	if got := c.str(adm, state, v); got != "true -1 infinity true" {
		t.Fatalf("the role after the re-key: %s", got)
	}
}

// TestWriteCanary_UnderAReadersLockEndsWithinItsBound: while a project role
// holds a reader's lock on the table, the write ends with a budget error at
// the session's statement bound; once the reader is gone a write succeeds.
func TestWriteCanary_UnderAReadersLockEndsWithinItsBound(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	pg := c.rawDial("postgres", nil)
	for _, s := range []string{"begin", "lock table supapace._backup_canary in access share mode"} {
		if _, err := pg.Exec(context.Background(), s); err != nil {
			t.Fatalf("control: %s: %v", s, pgsock.Clean(err))
		}
	}
	tg := c.target("supabase_admin")
	tg.Budget = pgsock.Budget{Statement: 2 * time.Second}
	bounded, err := pgsock.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	defer bounded.Close(context.Background())
	start := time.Now()
	err = WriteCanary(context.Background(), bounded)
	if err == nil || !pgsock.IsBudget(err) {
		t.Fatalf("the write under the lock: %v", err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("the write took %v", d)
	}
	if _, err := pg.Exec(context.Background(), "rollback"); err != nil {
		t.Fatal(pgsock.Clean(err))
	}
	if err := WriteCanary(context.Background(), adm); err != nil {
		t.Fatalf("the write after the reader left: %v", err)
	}
}

// TestHelper_ReturnsOnlyALoginWithAScramPasswordThatIsInForce: a role without
// the login right, an expired one, one with a password of another kind or
// with none is not returned; the argument is a name compared as it is.
func TestHelper_ReturnsOnlyALoginWithAScramPasswordThatIsInForce(t *testing.T) {
	c := startPoolerCluster(t)
	adm := c.dial("supabase_admin")
	for _, s := range []string{
		"create role t_ok login password 't-pw-" + rnd(8) + "'",
		"create role t_nologin nologin password 't-pw-" + rnd(8) + "'",
		"create role t_expired login password 't-pw-" + rnd(8) + "' valid until '2000-01-01'",
		"create role t_until login password 't-pw-" + rnd(8) + "' valid until '2999-01-01'",
		"create role t_other login password 'md5" + rnd(16) + "'",
		"create role t_none login",
	} {
		c.exec(adm, s)
	}
	for arg, want := range map[string]string{
		"t_ok": "1", "t_until": "1", "t_nologin": "0", "t_expired": "0", "t_other": "0", "t_none": "0",
		"T_OK": "0", "t_ok ": "0", "t_%": "0", "": "0", "t_ok' or 'x'='x": "0", "pg_monitor": "0",
	} {
		if got := c.str(adm, "select count(*)::text from supapace_pooler.get_auth($1)", arg); got != want {
			t.Errorf("%q: %s rows, want %s", arg, got, want)
		}
	}
	if got := c.str(adm, "select count(*)::text from supapace_pooler.get_auth(null)"); got != "0" {
		t.Errorf("null: %s rows", got)
	}
	if got := c.str(adm, "select username || ' ' || (password = (select rolpassword from pg_catalog.pg_authid where rolname = 't_ok'))::text from supapace_pooler.get_auth('t_ok')"); got != "t_ok true" {
		t.Errorf("the row of t_ok: %s", got)
	}
}

// TestCreateRestorePoint_OnlyTheServersForm: a location in another form than
// the server's own (upper-case hex, eight digits a part at most, nothing
// around it) is an error.
func TestCreateRestorePoint_OnlyTheServersForm(t *testing.T) {
	for answer, ok := range map[string]bool{"0/1A2B3C": true, "FFFFFFFF/FFFFFFFF": true, "0/1a": false, "0/123456789": false,
		" 0/1": false, "0/1\n": false, "0/": false, "/1": false, "0/1/2": false, "": false} {
		conn, rec := scriptedConn(t, func(string, bool) reply { return reply{oids: []uint32{25}, rows: [][]string{{answer}}} })
		got, err := CreateRestorePoint(context.Background(), conn, "t-point")
		if (err == nil) != ok || ok && got != answer || !ok && got != "" {
			t.Errorf("%q: %q %v", answer, got, err)
		}
		if st := rec.statements(); len(st) != 1 || st[0] != sqlRestorePoint {
			t.Errorf("%q: sent %q", answer, st)
		}
	}
}

// TestSetReadOnlySignal_OffLeavesNoSetting: the signal is one setting of the
// database postgres; taking it away leaves no setting of that name there, and
// either call may be repeated.
func TestSetReadOnlySignal_OffLeavesNoSetting(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	const held = `select coalesce(pg_catalog.string_agg(x, ','), '') from pg_catalog.pg_db_role_setting s
	  join pg_catalog.pg_database d on d.oid = s.setdatabase, pg_catalog.unnest(s.setconfig) x
	  where d.datname = 'postgres' and s.setrole = 0 and x like 'default_transaction_read_only=%'`
	for _, tc := range []struct {
		on   bool
		want string
	}{{true, "default_transaction_read_only=on"}, {true, "default_transaction_read_only=on"}, {false, ""}, {false, ""}} {
		if err := SetReadOnlySignal(context.Background(), adm, tc.on); err != nil {
			t.Fatal(err)
		}
		if got := c.str(adm, held); got != tc.want {
			t.Fatalf("signal %t: the database holds %q", tc.on, got)
		}
	}
	// The platform's own session is not reached by the signal.
	c.exec(adm, "select 1")
	if err := SetReadOnlySignal(context.Background(), adm, true); err != nil {
		t.Fatal(err)
	}
	if err := WriteCanary(context.Background(), c.dial("supabase_admin")); err != nil {
		t.Fatalf("a platform session opened under the signal cannot write: %v", err)
	}
}

// TestRekeyLogin_RemovalCauseIsBoundedAndClean: the cause of a failed removal
// is the server's code and message, sanitised and at most 256 bytes; no other
// field of the server's error and nothing of the statement is in it.
func TestRekeyLogin_RemovalCauseIsBoundedAndClean(t *testing.T) {
	const role = "supabase_read_only_user"
	v := newVerifier(t, role)
	msg := "t-cause \x1b[31m\r\n\u202e" + strings.Repeat("z", 5000)
	conn, _ := scriptedConn(t, func(sql string, run bool) reply {
		switch sql {
		case sqlTerminateRole:
			return reply{oids: []uint32{16}}
		case sqlUnlinkReadOnlyLargeObjects:
			if run {
				return reply{code: "53100", msg: msg}
			}
			return reply{oids: []uint32{25}}
		}
		return reply{}
	})
	res, err := RekeyLogin(context.Background(), conn, role, v)
	cause := res.LargeObjectsError
	if err != nil || !res.LargeObjectsLeft || res.LargeObjects != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if len(cause) != 256 || strings.ContainsAny(cause, "\x1b\r\n\u202e") || !strings.Contains(cause, "t-cause") ||
		!strings.HasPrefix(cause, "bootstrap: large objects of "+role+": ") {
		t.Errorf("cause of %d bytes: %.120q", len(cause), cause)
	}
	for _, not := range []string{"t-detail", "t-hint", "t-internal", "t-where", "lo_unlink", v} {
		if strings.Contains(cause, not) {
			t.Errorf("the cause holds %q", not)
		}
	}
	// A short cause carries the code.
	conn, _ = scriptedConn(t, func(sql string, run bool) reply {
		if sql == sqlUnlinkReadOnlyLargeObjects && run {
			return reply{code: "53100", msg: "t-full"}
		}
		if sql == sqlTerminateRole {
			return reply{oids: []uint32{16}}
		}
		return reply{oids: nil}
	})
	if res, err := RekeyLogin(context.Background(), conn, role, v); err != nil ||
		res.LargeObjectsError != "bootstrap: large objects of "+role+": ERROR: t-full (SQLSTATE 53100)" {
		t.Errorf("%+v %v", res, err)
	}
	// Without a failure there is none.
	conn, _ = scriptedConn(t, func(sql string, run bool) reply {
		if sql == sqlTerminateRole {
			return reply{oids: []uint32{16}}
		}
		if sql == sqlUnlinkReadOnlyLargeObjects {
			return reply{oids: []uint32{25}, rows: [][]string{{"1"}}}
		}
		return reply{}
	})
	if res, err := RekeyLogin(context.Background(), conn, role, v); err != nil || res != (RekeyResult{LargeObjects: 1}) {
		t.Errorf("%+v %v", res, err)
	}
}
