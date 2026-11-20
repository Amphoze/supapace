package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// deliveryEnv is a store, a sink declared on a node, and a sender of both.
type deliveryEnv struct {
	testDB
	sink *sink
	snd  *Sender
	logs *bytes.Buffer
	tok  string
}

func newDeliveryEnv(t *testing.T) *deliveryEnv {
	t.Helper()
	e := &deliveryEnv{testDB: newDB(t), sink: newSink(t, true), logs: &bytes.Buffer{}, tok: token()}
	n := newTestNode(t, false)
	if err := Save(n.p, n.k, e.sink.decl(e.tok)); err != nil {
		t.Fatal(err)
	}
	e.snd = NewSender(e.st, "node-a", n.load)
	e.snd.log = slog.New(slog.NewTextHandler(e.logs, nil))
	return e
}

func (e *deliveryEnv) docs(t *testing.T) []Document {
	t.Helper()
	var out []Document
	for _, r := range e.sink.got() {
		var d Document
		if err := json.Unmarshal(r.Body, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSender_DeliversOncePerHourPerSubjectAndCode(t *testing.T) {
	e := newDeliveryEnv(t)
	ctx := context.Background()
	must(t, e.st.RaiseAlert(ctx, "node", "disk-half", "warn", map[string]int64{"used_pct": 51}))
	must(t, e.st.RaiseAlert(ctx, "cp", "disk-half", "warn", nil))
	e.snd.round(ctx)
	d := e.docs(t)
	if len(d) != 2 || d[0].Node != "node-a" || d[0].Code != "disk-half" || d[0].Count != 1 {
		t.Fatalf("first round %+v", d)
	}
	// Raised again inside the hour, and a round with nothing raised: nothing sent.
	must(t, e.st.RaiseAlert(ctx, "node", "disk-half", "warn", map[string]int64{"used_pct": 52}))
	e.snd.round(ctx)
	if n := len(e.sink.got()); n != 2 {
		t.Fatalf("%d requests inside the hour", n)
	}
	// The hour passed: the row whose count moved is sent once, the other not.
	e.age(t, time.Hour+time.Minute)
	e.snd.round(ctx)
	e.snd.round(ctx)
	d = e.docs(t)
	if len(d) != 3 || d[2].Subject != "node" || d[2].Count != 2 || d[2].Figures["used_pct"] != 52 {
		t.Fatalf("after the hour %+v", d)
	}
	// A lift to page is sent at once, inside the hour.
	must(t, e.st.RaiseAlert(ctx, "cp", "disk-half", "page", nil))
	e.snd.round(ctx)
	if d = e.docs(t); len(d) != 4 || d[3].Subject != "cp" || d[3].Severity != "page" {
		t.Fatalf("lift %+v", d)
	}
}

func TestSender_RetriesAFailedDelivery(t *testing.T) {
	e := newDeliveryEnv(t)
	ctx := context.Background()
	must(t, e.st.RaiseAlert(ctx, "node", "disk-soft", "warn", nil))
	e.sink.setStatus(http.StatusServiceUnavailable)
	e.snd.round(ctx)
	e.snd.round(ctx)
	if ok, fail := e.snd.Status(); !ok.IsZero() || fail.IsZero() || len(e.sink.got()) != 2 {
		t.Fatalf("failing: ok %v fail %v, %d requests", ok, fail, len(e.sink.got()))
	}
	// Logged once while it lasts, without the address's path or query.
	if c := strings.Count(e.logs.String(), "delivery failed"); c != 1 || strings.Contains(e.logs.String(), e.tok) {
		t.Fatalf("logs %s", e.logs)
	}
	e.sink.setStatus(http.StatusAccepted)
	e.snd.round(ctx)
	e.snd.round(ctx)
	if ok, _ := e.snd.Status(); ok.IsZero() || len(e.sink.got()) != 3 {
		t.Fatalf("recovered: ok %v, %d requests", ok, len(e.sink.got()))
	}
}

func TestSender_ADownDestinationCostsOneAttemptARound(t *testing.T) {
	e := newDeliveryEnv(t)
	ctx := context.Background()
	for _, c := range []string{"disk-half", "disk-soft", "pusher-lag"} {
		must(t, e.st.RaiseAlert(ctx, "node", c, "warn", nil))
	}
	e.sink.setStatus(http.StatusInternalServerError)
	e.snd.round(ctx)
	if n := len(e.sink.got()); n != 1 {
		t.Fatalf("%d attempts in a round against a failing destination", n)
	}
	// Control: once it answers, the round delivers all three.
	e.sink.setStatus(http.StatusOK)
	e.snd.round(ctx)
	if n := len(e.sink.got()); n != 4 {
		t.Fatalf("%d requests", n)
	}
}

// unmarked is the store with its marks lost, as when the daemon stops
// between a delivery and its mark.
type unmarked struct{ *store.Store }

func (unmarked) MarkAlertSent(context.Context, store.Alert) error { return nil }

func TestSender_DeliveredButNotMarkedIsSentAgain(t *testing.T) {
	e := newDeliveryEnv(t)
	ctx := context.Background()
	must(t, e.st.RaiseAlert(ctx, "node", "disk-half", "warn", nil))
	lost := NewSender(unmarked{e.st}, "node-a", e.snd.load)
	lost.round(ctx)
	e.snd.round(ctx) // the next start
	e.snd.round(ctx)
	if d := e.docs(t); len(d) != 2 || d[0].Code != d[1].Code || d[1].Count != 1 {
		t.Fatalf("documents %+v", d)
	}
}

func TestSender_NoticeDetailNeverSent(t *testing.T) {
	e := newDeliveryEnv(t)
	ctx := context.Background()
	marker := token()
	must(t, e.st.EnsureBackupState(ctx, "cp"))
	must(t, e.st.Notice(ctx, "cp", "repo-space-low", "detail "+marker))
	e.snd.round(ctx)
	r := e.sink.got()
	if len(r) != 1 || bytes.Contains(r[0].Body, []byte(marker)) {
		t.Fatalf("requests %+v", r)
	}
	if d := e.docs(t)[0]; d.Code != "repo-space-low" || d.Subject != "cp" || d.Severity != "warn" {
		t.Fatalf("document %+v", d)
	}
}

func TestSender_ARowOffTheListIsSentAsUnlistedCodeOnce(t *testing.T) {
	e := newDeliveryEnv(t)
	ctx := context.Background()
	must(t, e.st.EnsureBackupState(ctx, "cp"))
	// A notice code no list names (one a job could have chosen), an alert
	// code no list names, and a listed alert beside them.
	must(t, e.st.Notice(ctx, "cp", "see-attacker-example", "x"))
	must(t, e.st.RaiseAlert(ctx, "node", "made-up", "page", map[string]int64{"n": 7}))
	must(t, e.st.RaiseAlert(ctx, "node", "disk-half", "warn", nil))
	e.snd.round(ctx)
	e.snd.round(ctx)
	got := map[string]Document{}
	for _, d := range e.docs(t) {
		got[d.Subject+"/"+d.Code+"/"+d.Severity] = d
	}
	n, a := got["cp/unlisted-code/warn"], got["node/unlisted-code/page"]
	if len(got) != 3 || len(e.docs(t)) != 3 || got["node/disk-half/warn"].Code == "" || n.Count != 1 || a.Count != 1 ||
		len(a.Figures) != 0 || a.FirstAt.IsZero() || n.Node != "node-a" {
		t.Fatalf("documents %+v", e.docs(t))
	}
	for _, r := range e.sink.got() {
		if bytes.Contains(r.Body, []byte("attacker")) || bytes.Contains(r.Body, []byte("made-up")) {
			t.Fatalf("the row's code was sent: %s", r.Body)
		}
	}
	if c := strings.Count(e.logs.String(), "sent as unlisted-code"); c != 2 || !strings.Contains(e.logs.String(), `code="\"see-attacker-example\""`) {
		t.Fatalf("logged %d times: %s", c, e.logs)
	}
	p, err := e.st.PendingAlerts(ctx, 0, 64)
	must(t, err)
	if len(p) != 0 {
		t.Fatalf("still pending %+v", p)
	}
	// A failed delivery of the fixed form leaves the row pending.
	must(t, e.st.RaiseAlert(ctx, "node", "made-up", "page", nil))
	e.age(t, 2*time.Hour)
	e.sink.setStatus(http.StatusInternalServerError)
	e.snd.round(ctx)
	if p, _ := e.st.PendingAlerts(ctx, 0, 64); len(p) != 1 {
		t.Fatalf("pending after a failed delivery %+v", p)
	}
}

func TestUnlisted_FixedForm(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		row      store.Alert
		subj, sv string
	}{
		{store.Alert{Subject: "cp", Code: "x", Severity: "warn"}, "cp", "warn"},
		{store.Alert{Subject: "bad\nsubject", Code: "x", Severity: "warn"}, "node", "warn"},
		{store.Alert{Subject: "abcdefghij0123456789", Code: "x", Severity: "loud"}, "abcdefghij0123456789", "page"},
		{store.Alert{Subject: "proj", Code: "test", Severity: ""}, "node", "page"},
	} {
		tc.row.Count, tc.row.FirstAt, tc.row.LastAt, tc.row.Figures = 3, now, now, map[string]int64{"bad name": 1}
		got := unlisted("node-a", tc.row)
		if got.Code != "unlisted-code" || got.Subject != tc.subj || got.Severity != tc.sv || got.Count != 3 || got.Figures != nil ||
			!got.FirstAt.Equal(now) || checkDoc(got) != nil {
			t.Errorf("%+v -> %+v", tc.row, got)
		}
	}
}

func TestSender_UndeclaredSendsNothingAndKeepsRows(t *testing.T) {
	e := newDeliveryEnv(t)
	ctx := context.Background()
	must(t, e.st.RaiseAlert(ctx, "node", "disk-half", "warn", nil))
	none := NewSender(e.st, "node-a", func() (Declaration, bool, error) { return Declaration{}, false, nil })
	none.log = e.snd.log
	none.round(ctx)
	none.round(ctx)
	if p, err := e.st.PendingAlerts(ctx, time.Hour, 64); err != nil || len(p) != 1 {
		t.Fatalf("pending %v %v", p, err)
	}
	if c := strings.Count(e.logs.String(), "no destination declared"); c != 1 {
		t.Fatalf("logged %d times", c)
	}
	// Run: a round at once, and it returns when its context ends.
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.snd.Run(rctx); close(done) }()
	// At once: well before the first 15 s tick.
	for deadline := time.Now().Add(5 * time.Second); len(e.sink.got()) == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("Run made no round at once")
		}
	}
	cancel()
	<-done
}
