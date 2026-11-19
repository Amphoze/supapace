package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// walkOp is one operation of a walked ref as the walk recorded it.
type walkOp struct {
	id          int64
	kind, state string
}

// walkAction submits kind and ends it failed: before (nothing changed) or
// after (the project moved on: restarting, restoring or deleting).
type walkAction struct{ kind, when string }

func (a walkAction) String() string { return a.kind + "/" + a.when }

// walkAccepts is the admission rule written from the decisions: one open
// operation per ref; an active project takes each kind; a project left
// restarting takes a restart or a delete when the newest of its restarts and
// restores is failed, and a restore when its newest operation is a failed
// restart or restore; a project left restoring takes a restore after a failed
// restart or restore, and a delete after a failed restore. It returns
// whether kind is accepted and whether it supersedes the newest operation.
func walkAccepts(state string, ops []walkOp, kind string) (ok, supersede bool) {
	var newest, newestRR *walkOp
	for i := range ops {
		newest = &ops[i]
		if ops[i].kind == "restart" || ops[i].kind == "restore" {
			newestRR = &ops[i]
		}
	}
	failedRR := newest != nil && newest.state == "failed" && (newest.kind == "restart" || newest.kind == "restore")
	switch state {
	case "active":
		return true, false
	case "restarting":
		switch kind {
		case "restart", "delete":
			return newestRR != nil && newestRR.state == "failed", false
		case "restore":
			return failedRR, failedRR
		}
	case "restoring":
		switch kind {
		case "restore":
			return failedRR, failedRR
		case "delete":
			ok := newest != nil && newest.state == "failed" && newest.kind == "restore"
			return ok, ok
		}
	}
	return false, false
}

// TestSubmit_WalkOfFailedOperations walks every sequence of up to four
// restarts, restores and deletes, each failing before or after it changed
// the project's state, and checks after every step: the store admits exactly
// what the rule admits and supersedes what it supersedes; while an operation
// is open (pending or waiting for its job) no submit and no retry is
// accepted; a superseded operation cannot be retried; a project left
// restarting or restoring accepts a submit or can retry its newest operation.
func TestSubmit_WalkOfFailedOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("long walk")
	}
	s := newStore(t, testConfig())
	ctx := context.Background()
	var node string
	must(t, s.pool.QueryRow(ctx, "select id from node").Scan(&node))
	actions := []walkAction{}
	for _, k := range []string{"restart", "restore", "delete"} {
		for _, w := range []string{"before", "after"} {
			actions = append(actions, walkAction{k, w})
		}
	}
	n := 0
	submit := func(r, kind string) (int64, error) {
		if kind == "restore" {
			id, _, err := s.SubmitRestore(ctx, r, json.RawMessage(`{"to":"latest"}`))
			return id, err
		}
		var gen int64
		must(t, s.pool.QueryRow(ctx, "select generation from project where ref = $1", r).Scan(&gen))
		return s.SubmitOperation(ctx, r, kind, nil, gen, time.Now())
	}
	var walk func(prefix []walkAction)
	walk = func(prefix []walkAction) {
		n++
		r := fmt.Sprintf("walk%016d", n)
		sqlExec(t, s, `insert into project (ref, name, node_id, state, epoch, mem_mb, pids, config)
			values ($1, 'walk', $2, 'active', 1, 0, 0, $3)`, r, node, defaultConfig)
		var ops []walkOp
		state := "active"
		path := func() string { return fmt.Sprint(prefix) }
		for i, a := range prefix {
			ok, sup := walkAccepts(state, ops, a.kind)
			id, err := submit(r, a.kind)
			if ok != (err == nil) {
				t.Fatalf("%s step %d: %s of a %s project: accepted %v, the rule says %v (%v)", path(), i, a.kind, state, err == nil, ok, err)
			}
			if err != nil {
				wantErr(t, err, ErrConflict)
				return // refused: the walk below this step is the walk without it
			}
			if sup {
				ops[len(ops)-1].state = "superseded"
			}
			for _, o := range ops {
				if got := opState(t, s, o.id).State; got != o.state {
					t.Fatalf("%s step %d: operation %d (%s) is %s, want %s", path(), i, o.id, o.kind, got, o.state)
				}
			}
			ops = append(ops, walkOp{id, a.kind, "pending"})
			// Open (pending, then parked): nothing else is accepted.
			for _, open := range []string{"pending", "waiting_job"} {
				sqlExec(t, s, "update operation set state = $2 where id = $1", id, open)
				for _, k := range []string{"restart", "restore", "delete"} {
					if _, err := submit(r, k); !errors.Is(err, ErrConflict) {
						t.Fatalf("%s step %d: %s beside a %s operation: %v", path(), i, k, open, err)
					}
				}
				for _, o := range ops[:len(ops)-1] {
					if err := s.RetryOperation(ctx, o.id); !errors.Is(err, ErrConflict) {
						t.Fatalf("%s step %d: retry of %d beside a %s operation: %v", path(), i, o.id, open, err)
					}
				}
				if c := count(t, s, "select count(*) from operation where ref = $1 and state in "+openStates, r); c != 1 {
					t.Fatalf("%s step %d: %d open operations", path(), i, c)
				}
			}
			sqlExec(t, s, "update operation set state = 'pending' where id = $1", id)
			must(t, s.StartOperation(ctx, id))
			if a.when == "after" {
				switch a.kind {
				case "restart":
					var gen int64
					must(t, s.pool.QueryRow(ctx, "select generation from project where ref = $1", r).Scan(&gen))
					must(t, s.BeginRestart(ctx, r, gen+1, defaultConfig))
					state = "restarting"
				case "restore":
					must(t, s.SetProjectRestoring(ctx, r, id))
					state = "restoring"
				case "delete":
					must(t, s.SetProjectState(ctx, r, "deleting"))
					state = "deleting"
				}
			}
			must(t, s.FinishOperation(ctx, id, "failed", "internal: walk"))
			ops[len(ops)-1].state = "failed"
			// A superseded operation is final; a failed restore is retried
			// only while it is the newest.
			for j, o := range ops {
				if o.state == "superseded" || o.kind == "restore" && o.state == "failed" && j < len(ops)-1 {
					if err := s.RetryOperation(ctx, o.id); !errors.Is(err, ErrConflict) {
						t.Fatalf("%s step %d: retry of %s %s %d: %v", path(), i, o.state, o.kind, o.id, err)
					}
				}
			}
		}
		// A project an operation left behind is never stuck: it accepts a
		// submit, or its newest operation is failed and can be retried.
		if state == "restarting" || state == "restoring" {
			accepts := false
			for _, k := range []string{"restart", "restore", "delete"} {
				ok, _ := walkAccepts(state, ops, k)
				accepts = accepts || ok
			}
			if !accepts && (len(ops) == 0 || ops[len(ops)-1].state != "failed") {
				t.Fatalf("%s: a %s project accepts nothing and cannot retry", path(), state)
			}
		}
		if len(prefix) == 4 {
			return
		}
		for _, a := range actions {
			walk(append(slices.Clone(prefix), a))
		}
	}
	walk(nil)
	t.Logf("%d sequences walked", n)
}

// The supersede guard: an operation that is no longer failed is never
// superseded, and nothing else of the step is written.
func TestSupersede_RefusesAnOperationNoLongerFailed(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, _, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	must(t, s.SetSlot(ctx, r, id))
	job := addJob(t, s, r, id, "queued")
	for _, st := range []string{"pending", "running", "waiting_job", "done", "superseded"} {
		sqlExec(t, s, "update operation set state = $2 where id = $1", id, st)
		err := s.tx(ctx, func(tx pgx.Tx) error { return supersedeOp(ctx, tx, r, id) })
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "no longer failed") {
			t.Fatalf("supersede of a %s operation: %v", st, err)
		}
		wantOpState(t, s, id, st)
	}
	if slotOf(t, s, r) != id {
		t.Fatal("slot cleared")
	}
	if st, _ := jobState(t, s, job); st != "queued" {
		t.Fatalf("job %s", st)
	}
	// Control.
	sqlExec(t, s, "update operation set state = 'failed' where id = $1", id)
	must(t, s.tx(ctx, func(tx pgx.Tx) error { return supersedeOp(ctx, tx, r, id) }))
	wantOpState(t, s, id, "superseded")
}

// A migration that fails part-way records nothing: the version, the checks
// and the columns are version 1's.
func TestMigrate_PartialMigrationRollsBack(t *testing.T) {
	s := v1Store(t)
	ctx := context.Background()
	r := newActive(t, s, 1)
	// A table the migration creates near its end exists already.
	sqlExec(t, s, "create table offsite_info_version (x int)")
	if err := s.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "migration_2.sql") {
		t.Fatalf("Migrate over a conflicting table: %v", err)
	}
	if v := schemaVer(t, s); v != 1 {
		t.Fatalf("schema version %d after a failed migration", v)
	}
	if _, err := s.pool.Exec(ctx, "update project set state = 'restoring' where ref = $1", r); err == nil {
		t.Fatal("the new project check survived the rollback")
	}
	for _, q := range []string{
		"select count(*) from information_schema.columns where table_name = 'project' and column_name = 'slot_op'",
		"select count(*) from information_schema.tables where table_name = 'backup_state'",
		"select count(*) from pg_indexes where indexname = 'operation_open' and indexdef like '%waiting_job%'",
	} {
		if c := count(t, s, q); c != 0 {
			t.Fatalf("%s: %d after the rollback", q, c)
		}
	}
	// Control: without the conflict it migrates.
	sqlExec(t, s, "drop table offsite_info_version")
	must(t, s.Migrate(ctx))
	if v := schemaVer(t, s); v != schemaVersion {
		t.Fatalf("schema version %d", v)
	}
}

// Two daemons starting at once on a version-1 database: one migrates, the
// other then finds the new version and does nothing.
func TestMigrate_ConcurrentUpgradesFromV1(t *testing.T) {
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		s := v1Store(t)
		stores := make([]*Store, 2)
		for i := range stores {
			var err error
			stores[i], err = Open(ctx, sockDir)
			must(t, err)
			defer stores[i].Close()
		}
		for i, err := range race(2, func(i int) error { return stores[i].Migrate(ctx) }) {
			if err != nil {
				t.Fatalf("round %d, migrate %d: %v", round, i, err)
			}
		}
		if v, n := schemaVer(t, s), count(t, s, "select count(*) from cp_meta"); v != schemaVersion || n != 1 {
			t.Fatalf("round %d: version %d, cp_meta rows %d", round, v, n)
		}
	}
}

// Every embedded migration is in the list and every listed one is embedded,
// numbered from 2 in order: a new version is a file and one list element.
func TestMigrate_FilesMatchTheList(t *testing.T) {
	files, err := fs.Glob(migrationFiles, "migration_*.sql")
	must(t, err)
	sort.Slice(files, func(i, j int) bool {
		return len(files[i]) < len(files[j]) || len(files[i]) == len(files[j]) && files[i] < files[j]
	})
	if !slices.Equal(files, migrations[:]) {
		t.Fatalf("embedded %v, listed %v", files, migrations)
	}
	for i, name := range migrations {
		if want := fmt.Sprintf("migration_%d.sql", i+2); name != want {
			t.Fatalf("element %d is %s, want %s", i, name, want)
		}
	}
	if schemaVersion != 1+len(migrations) {
		t.Fatalf("schemaVersion %d", schemaVersion)
	}
}

// schemaTables is every table the base schema and the migrations create.
func schemaTables(t *testing.T) []string {
	t.Helper()
	text := schemaSQL
	for _, name := range migrations {
		b, err := migrationFiles.ReadFile(name)
		must(t, err)
		text += "\n" + string(b)
	}
	var names []string
	for _, m := range regexp.MustCompile(`(?m)^create table (\w+)`).FindAllStringSubmatch(text, -1) {
		names = append(names, m[1])
	}
	sort.Strings(names)
	return names
}

// The tables of a migrated database are exactly those the files create.
func TestMigrate_TablesAreTheFilesTables(t *testing.T) {
	s := newStore(t, testConfig())
	rows, err := s.pool.Query(context.Background(),
		"select table_name::text from information_schema.tables where table_schema = 'public' order by 1")
	must(t, err)
	var got []string
	for rows.Next() {
		var n string
		must(t, rows.Scan(&n))
		got = append(got, n)
	}
	must(t, rows.Err())
	if want := schemaTables(t); !slices.Equal(got, want) || len(want) < 15 {
		t.Fatalf("tables %v, want %v", got, want)
	}
}

// A configuration stored before the three new members existed reads back,
// marshals and is written back unchanged.
func TestProjectConfig_OldRowRoundTrip(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	old := `{"disk_quota_mb":8192,"mem_mb":512,"guc":{"work_mem":"4MB"}}`
	sqlExec(t, s, "update project set config = $2::jsonb where ref = $1", r, old)
	var stored string
	must(t, s.pool.QueryRow(ctx, "select config::text from project where ref = $1", r).Scan(&stored))
	p, err := s.GetProject(ctx, r)
	must(t, err)
	b, err := json.Marshal(p.Config)
	must(t, err)
	if string(b) != old {
		t.Fatalf("marshalled %s, stored before %s", b, old)
	}
	must(t, s.BumpGeneration(ctx, r, p.Generation+1, p.Config))
	var again string
	must(t, s.pool.QueryRow(ctx, "select config::text from project where ref = $1", r).Scan(&again))
	if again != stored {
		t.Fatalf("written back %s, was %s", again, stored)
	}
}
