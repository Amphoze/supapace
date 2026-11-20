package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func pending(t *testing.T, s *Store, repeat time.Duration) map[string]Alert {
	t.Helper()
	as, err := s.PendingAlerts(context.Background(), repeat, 64)
	must(t, err)
	m := map[string]Alert{}
	for _, a := range as {
		m[a.Subject+"/"+a.Code] = a
	}
	return m
}

func TestAlerts_UnionWithNoticesAndRepeat(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	must(t, s.RaiseAlert(ctx, "node", "disk-half", "warn", map[string]int64{"used_pct": 51}))
	must(t, s.Notice(ctx, r, "offsite-differs", "a detail a job supplied"))
	p := pending(t, s, time.Hour)
	a, n := p["node/disk-half"], p[r+"/offsite-differs"]
	if len(p) != 2 || a.FromNotice || a.Severity != "warn" || a.Figures["used_pct"] != 51 || a.Count != 1 {
		t.Fatalf("pending %+v", p)
	}
	if !n.FromNotice || n.Severity != "warn" || len(n.Figures) != 0 || n.Count != 1 {
		t.Fatalf("notice %+v", n)
	}
	if strings.Contains(fmt.Sprintf("%+v", p), "detail") {
		t.Fatal("a notice's detail was read")
	}
	must(t, s.MarkAlertSent(ctx, a))
	must(t, s.MarkAlertSent(ctx, n))
	if p := pending(t, s, time.Hour); len(p) != 0 {
		t.Fatalf("pending after sending %+v", p)
	}
	// Raised again: the count moved, but the hour has not passed.
	must(t, s.RaiseAlert(ctx, "node", "disk-half", "warn", nil))
	must(t, s.Notice(ctx, r, "offsite-differs", "x"))
	if p := pending(t, s, time.Hour); len(p) != 0 {
		t.Fatalf("pending inside the hour %+v", p)
	}
	if p := pending(t, s, 0); len(p) != 2 || p["node/disk-half"].Count != 2 || p[r+"/offsite-differs"].Count != 2 {
		t.Fatalf("pending once the repeat passed %+v", p)
	}
	// The limit holds across both sources.
	as, err := s.PendingAlerts(ctx, 0, 1)
	must(t, err)
	if len(as) != 1 {
		t.Fatalf("%d with limit 1", len(as))
	}
	open, err := s.OpenAlerts(ctx, "node")
	must(t, err)
	if len(open) != 1 || open[0].Code != "disk-half" {
		t.Fatalf("open %+v", open)
	}
}

func TestAlerts_ClearedThenRaisedAgainIsPending(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	must(t, s.RaiseAlert(ctx, "cp", "pusher-lag", "warn", nil))
	a := pending(t, s, time.Hour)["cp/pusher-lag"]
	must(t, s.MarkAlertSent(ctx, a))
	must(t, s.ClearAlert(ctx, "cp", "pusher-lag"))
	if open, _ := s.OpenAlerts(ctx, ""); len(open) != 0 {
		t.Fatalf("open after clear %+v", open)
	}
	if p := pending(t, s, 0); len(p) != 0 {
		t.Fatalf("a cleared row is pending %+v", p)
	}
	must(t, s.RaiseAlert(ctx, "cp", "pusher-lag", "warn", nil))
	if p := pending(t, s, time.Hour); p["cp/pusher-lag"].Count != 2 {
		t.Fatalf("raised again after a clear, not pending: %+v", p)
	}
}

func TestAlerts_OpenRowKeepsTheHigherSeverity_ALiftIsPendingAtOnce(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	sev := func() string {
		open, err := s.OpenAlerts(ctx, "node")
		must(t, err)
		if len(open) != 1 {
			t.Fatalf("open %+v", open)
		}
		return open[0].Severity
	}
	send := func() { must(t, s.MarkAlertSent(ctx, pending(t, s, time.Hour)["node/clock-jump"])) }
	// warn, then page inside the hour: page, pending now.
	must(t, s.RaiseAlert(ctx, "node", "clock-jump", "warn", nil))
	send()
	must(t, s.RaiseAlert(ctx, "node", "clock-jump", "page", nil))
	if a, ok := pending(t, s, time.Hour)["node/clock-jump"]; !ok || a.Severity != "page" || sev() != "page" {
		t.Fatalf("a lift is not pending at once: %+v", a)
	}
	send()
	// page, then warn: still page, and not pending before its hour.
	must(t, s.RaiseAlert(ctx, "node", "clock-jump", "warn", nil))
	if _, ok := pending(t, s, time.Hour)["node/clock-jump"]; ok || sev() != "page" {
		t.Fatalf("a lower raise: pending %v, severity %s", ok, sev())
	}
	// cleared, then raised as warn: warn.
	must(t, s.ClearAlert(ctx, "node", "clock-jump"))
	must(t, s.RaiseAlert(ctx, "node", "clock-jump", "warn", nil))
	if sev() != "warn" {
		t.Fatalf("re-opened as %s", sev())
	}
}

func TestRaiseAlert_Refusals(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for _, c := range []struct{ subject, code, severity string }{
		{"elsewhere", "disk-half", "warn"}, {"node", "", "warn"}, {"node", "Disk Half", "warn"},
		{"node", strings.Repeat("a", 65), "warn"}, {"node", "disk-half", "info"},
	} {
		wantErr(t, s.RaiseAlert(ctx, c.subject, c.code, c.severity, nil), ErrConflict)
	}
	big := map[string]int64{}
	for i := 0; i < 17; i++ {
		big[fmt.Sprintf("f%d", i)] = 1
	}
	wantErr(t, s.RaiseAlert(ctx, "node", "disk-half", "warn", big), ErrConflict)
	wantErr(t, s.RaiseAlert(ctx, "node", "disk-half", "warn", map[string]int64{"Bad Name": 1}), ErrConflict)
	// Rows of one subject are bounded; an existing row is always raised.
	for i := 0; i < maxAlertsPerSubject; i++ {
		must(t, s.RaiseAlert(ctx, "cp", fmt.Sprintf("code-%d", i), "warn", nil))
	}
	wantErr(t, s.RaiseAlert(ctx, "cp", "one-more", "warn", nil), ErrConflict)
	must(t, s.RaiseAlert(ctx, "cp", "code-0", "page", nil))
	must(t, s.RaiseAlert(ctx, "node", "one-more", "warn", nil))
	if n := count(t, s, "select count(*) from alert"); n != maxAlertsPerSubject+1 {
		t.Fatalf("%d rows", n)
	}
}
