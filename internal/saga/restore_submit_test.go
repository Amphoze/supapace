package saga

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/store"
)

// ───────── restore: the submit ─────────

func (x *rx) restoreOps() []store.Operation {
	x.e.t.Helper()
	ops, err := x.e.st.ListOperations(context.Background(), x.ref)
	must(x.e.t, err)
	var out []store.Operation
	for _, o := range ops {
		if o.Kind == "restore" {
			out = append(out, o)
		}
	}
	return out
}

func wantConflict(t *testing.T, err error, text string) {
	t.Helper()
	if !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), text) {
		t.Fatalf("got %v, want a conflict saying %q", err, text)
	}
}

func TestRestoreSubmit_SetByLabelFromRecord(t *testing.T) {
	x := newRx(t)
	for _, c := range []struct {
		to   string
		want int
	}{
		{"latest", 2},
		{x.base.Add(90 * time.Minute).Format(time.RFC3339), 1}, // between B's and C's stop
		{x.base.Add(time.Hour).Format(time.RFC3339), 1},        // at B's stop
		{"lsn:0/6000000", 1},
		{"lsn:0/7000100", 2},
	} {
		id := x.mustSubmit(c.to, 0, "")
		p := x.params(id)
		if raw(p, "set") != `"`+x.sets[c.want]+`"` || raw(p, "from") != `"local"` || raw(p, "to") != `"`+c.to+`"` {
			t.Fatalf("%s: %s", c.to, x.e.op(id).Params)
		}
		if raw(p, "set_start_segment") != `"`+[]string{seg2, seg4, seg6}[c.want]+`"` {
			t.Fatalf("%s: start segment %s", c.to, raw(p, "set_start_segment"))
		}
		sql(t, "update operation set state = 'failed' where id = $1", id) // the next submit supersedes it
	}
}

func TestRestoreSubmit_OutOfWindow(t *testing.T) {
	x := newRx(t)
	bs, err := x.e.st.GetBackupState(context.Background(), x.ref)
	must(t, err)
	for _, to := range []string{x.base.Add(-time.Minute).Format(time.RFC3339), "lsn:0/3000000"} {
		_, err := x.submit(to, 0, "")
		var we *store.WindowError
		if !errors.As(err, &we) || !we.From.Equal(x.base) || !we.To.Equal(*bs.LastPushOK) {
			t.Fatalf("%s: %v", to, err)
		}
	}
	if len(x.restoreOps()) != 0 {
		t.Fatal("a refused restore was submitted")
	}
	// Control: the oldest set's own stop is inside.
	x.mustSubmit(x.base.Format(time.RFC3339), 0, "")
}

func TestRestoreSubmit_FutureTime(t *testing.T) {
	x := newRx(t)
	_, err := x.submit(time.Now().Add(time.Hour).UTC().Format(time.RFC3339), 0, "")
	var we *store.WindowError
	if !errors.As(err, &we) || len(x.restoreOps()) != 0 {
		t.Fatalf("got %v", err)
	}
	x.mustSubmit(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), 0, "")
}

func TestRestoreSubmit_AbandonedTimelineRefused(t *testing.T) {
	x := newRx(t)
	x.timeline(2, "abandoned", 0)
	x.timeline(3, "pending", x.create)
	for _, tl := range []int{2, 3, 4} {
		_, err := x.submit("latest", tl, "")
		wantConflict(t, err, "is not a recorded timeline")
	}
	if len(x.restoreOps()) != 0 {
		t.Fatal("a refused restore was submitted")
	}
	x.mustSubmit("latest", 1, "")
}

func TestRestoreSubmit_QuotaFullRefused(t *testing.T) {
	x := newRx(t)
	x.ag.quotaFull.Store(true)
	_, err := x.submit("latest", 0, "")
	wantConflict(t, err, "disk quota full; restart the project with a larger quota first")
	x.ag.quotaFull.Store(false)
	x.mustSubmit("latest", 0, "")
}

func TestRestoreSubmit_NoBackupRefused(t *testing.T) {
	x := newRx(t)
	sql(t, "delete from backup_set where subject = $1", x.ref)
	_, err := x.submit("latest", 0, "")
	wantConflict(t, err, "no completed backup yet; the first full backup follows the project's stanza; see 'supapace project backups "+x.ref+"'")
	// A layout-1 project has none either.
	ref := x.e.active()
	b, _ := json.Marshal(map[string]any{"to": "latest", "timeline": 0, "from": ""})
	_, err = x.r.Submit(context.Background(), "restore", ref, b)
	wantConflict(t, err, "no completed backup")
}

func TestRestoreSubmit_SetOlderThanTheSeedIsOffsiteOnly(t *testing.T) {
	x := newRx(t)
	x.declare()
	must(t, x.e.st.SetSeeded(context.Background(), x.ref, x.base.Add(90*time.Minute))) // after B's stop, before C's
	b := x.base.Add(time.Hour).Format(time.RFC3339)
	id := x.mustSubmit(b, 0, "")
	if p := x.params(id); raw(p, "from") != `"offsite"` || raw(p, "set") != `"`+x.sets[1]+`"` {
		t.Fatalf("defaulted source: %s", x.e.op(id).Params)
	}
	sql(t, "update operation set state = 'failed' where id = $1", id)
	_, err := x.submit(b, 0, "local")
	wantConflict(t, err, "this backup set is restorable from the off-site store only; restore without --from local")
	// A set that stopped after the seed stays local.
	id = x.mustSubmit("latest", 0, "")
	if p := x.params(id); raw(p, "from") != `"local"` || raw(p, "set") != `"`+x.sets[2]+`"` {
		t.Fatalf("set after the seed: %s", x.e.op(id).Params)
	}
}

func TestRestoreSubmit_OffsiteNeedsDeclaration(t *testing.T) {
	x := newRx(t)
	x.declare()
	for state, text := range map[string]string{"undeclared": "off-site store not declared; restore without --from offsite, or declare it with 'supapaced offsite set'",
		"partial": "off-site store partly declared; run 'supapaced offsite set' on this node to give the projects' bucket its credentials"} {
		x.e.jobs.offsite.Store(state)
		_, err := x.submit("latest", 0, "offsite")
		wantConflict(t, err, text)
	}
	if len(x.restoreOps()) != 0 {
		t.Fatal("a refused restore was submitted")
	}
	x.e.jobs.offsite.Store("declared")
	x.mustSubmit("latest", 0, "offsite")
}

func TestRestoreSubmit_OffsiteNeedsReplicatedListedSet(t *testing.T) {
	const none = "no backup of the project is completely off-site yet"
	x := newRx(t)
	x.e.jobs.offsite.Store("declared")
	// Chosen.
	_, err := x.submit("latest", 0, "offsite")
	wantConflict(t, err, none)
	// Defaulted by the seed rule.
	must(t, x.e.st.SetSeeded(context.Background(), x.ref, time.Now()))
	_, err = x.submit("latest", 0, "")
	wantConflict(t, err, none)
	// Replicated without listed_at is not a candidate either.
	sql(t, "update backup_set set replicated = true where subject = $1", x.ref)
	_, err = x.submit("latest", 0, "offsite")
	wantConflict(t, err, none)
	// Forced by a replaced node.
	sql(t, "update backup_state set seeded_at = null where subject = $1", x.ref)
	x.replaced()
	_, err = x.submit("latest", 0, "")
	wantConflict(t, err, none)
	// B is completely off-site, C is not: B is restored.
	sql(t, "update backup_set set listed_at = stop_at where subject = $1 and label = $2", x.ref, x.sets[1])
	id := x.mustSubmit("latest", 0, "")
	if p := x.params(id); raw(p, "from") != `"offsite"` || raw(p, "set") != `"`+x.sets[1]+`"` {
		t.Fatalf("%s", x.e.op(id).Params)
	}
}

func TestRestoreSubmit_AcceptedForUnadoptedProject(t *testing.T) {
	// A node that holds nothing of the project (after a recovery the boot has
	// not adopted it, and cannot): accepted, from the off-site store.
	x := newRx(t)
	x.declare()
	x.replaced()
	id := x.mustSubmit("latest", 0, "")
	if op := x.e.op(id); op.State != "pending" || raw(x.params(id), "from") != `"offsite"` {
		t.Fatalf("%+v", op)
	}
}

func TestRestoreSubmit_SupersedesAndClearsSlot(t *testing.T) {
	x := newRx(t)
	id := x.mustSubmit("latest", 0, "")
	sql(t, "update operation set state = 'failed', attempts = 5 where id = $1", id)
	sql(t, "update project set state = 'restoring', slot_op = $2 where ref = $1", x.ref, id)
	j, err := x.e.st.SubmitJob(context.Background(), store.NewJob{Subject: x.ref, Lane: "backup", Kind: "check", DeadlineS: 60})
	must(t, err)
	sql(t, "update backup_job set op_id = $2 where id = $1", j, id)
	id2 := x.mustSubmit("latest", 0, "")
	if op := x.e.op(id); op.State != "superseded" || op.Attempts != 5 {
		t.Fatalf("superseded: %+v", op)
	}
	if s := x.slot(); s != "" {
		t.Fatalf("slot %s", s)
	}
	if op := x.e.op(id2); op.State != "pending" || op.Attempts != 0 {
		t.Fatalf("new: %+v", op)
	}
}

func TestSubmitRestore_RefusesATargetThePinsRefuse(t *testing.T) {
	x := newRx(t)
	for _, c := range []struct{ body, field string }{
		{`{"to":"9999-12-31T23:00:00-05:00","timeline":0,"from":""}`, "year"}, // year 10000 in UTC
		{`{"to":"lsn:0/0","timeline":0,"from":""}`, "position"},
		{`{"to":"latest","timeline":02,"from":""}`, "timeline"},
	} {
		_, err := x.r.Submit(context.Background(), "restore", x.ref, json.RawMessage(c.body))
		if err == nil || !strings.Contains(err.Error(), c.field) || strings.Contains(err.Error(), c.body) {
			t.Fatalf("%s: %v", c.body, err)
		}
		if strings.Contains(c.body, "lsn:") && !errors.Is(err, pgconf.ErrGUCValue) {
			t.Fatalf("%s: not the pins' refusal: %v", c.body, err)
		}
	}
	if len(x.restoreOps()) != 0 {
		t.Fatal("a refused target was submitted")
	}
	x.mustSubmit("lsn:0/7000100", 0, "")
}

func TestSubmitRestore_RulesRunBeforeTheStoreCall(t *testing.T) {
	x := newRx(t)
	// An open operation: the store would answer with its own conflict.
	open := x.e.restart(x.r, x.ref, layout2)
	_, err := x.submit("lsn:0/0", 0, "")
	if !errors.Is(err, pgconf.ErrGUCValue) {
		t.Fatalf("target: %v", err)
	}
	_, err = x.submit("latest", 0, "offsite")
	wantConflict(t, err, "off-site store not declared; restore without --from offsite, or declare it with 'supapaced offsite set'")
	x.ag.quotaFull.Store(true)
	_, err = x.submit("latest", 0, "")
	wantConflict(t, err, "disk quota full")
	x.ag.quotaFull.Store(false)
	_, err = x.submit("latest", 0, "")
	wantConflict(t, err, "operation")
	if x.e.op(open).Kind != "restart" || len(x.restoreOps()) != 0 {
		t.Fatal("submitted")
	}
}
