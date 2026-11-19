package adminapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// A restart to a disk quota below the usage plus the headroom is refused at
// once with its own code, the figures and the smallest accepted value, and
// reaches no operation; the bound itself, and a restart that keeps the
// quota, are accepted.
func TestAPI_RestartQuotaBelowUsage(t *testing.T) {
	pr := "/v1/projects/" + demoRef + "/restart"
	least := 2300 + store.QuotaHeadroomMB
	e := newEnv(t)
	e.active(t, demoRef)
	e.ops.used = 2300 << 20
	eb := e.wantCode(t, "POST", pr, fmt.Sprintf(`{"disk_quota_mb":%d}`, least-1), 409, "quota_below_usage")
	want := fmt.Sprintf("disk_quota_mb %d is below the project's usage of 2300 MiB plus the %d MiB a clean cluster start needs; "+
		"the smallest accepted value is %d", least-1, store.QuotaHeadroomMB, least)
	if eb.Message != want {
		t.Fatalf("message %q", eb.Message)
	}
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("refused restart reached Ops: %v", calls)
	}
	if uid := *e.project(t, demoRef).UID; len(e.ops.usedUIDs) != 1 || e.ops.usedUIDs[0] != uid {
		t.Fatalf("usage read for %v, want the project's uid %d", e.ops.usedUIDs, uid)
	}
	e.ops.used = 1 << 40
	e.wantOK(t, "POST", pr, `{"set":{"max_connections":"200"},"disk_quota_mb":8192}`, 202) // the quota kept: no check

	e2 := newEnv(t)
	e2.active(t, demoRef)
	e2.ops.used = 2300 << 20
	e2.wantOK(t, "POST", pr, fmt.Sprintf(`{"disk_quota_mb":%d}`, least), 202)

	// A usage that cannot be read refuses the change (fixed internal error).
	e3 := newEnv(t)
	e3.active(t, demoRef)
	e3.ops.usedErr = errors.New("xfs_quota: no such mount")
	e3.wantCode(t, "POST", pr, `{"disk_quota_mb":16384}`, 500, "internal")
}

// A project left restarting by a failed restart takes a new restart (its
// quota checked like any other) or a delete through the API; abort says so.
func TestAPI_StrandedProjectExits(t *testing.T) {
	ctx := context.Background()
	pr := "/v1/projects/" + demoRef + "/restart"
	strand := func(e *env) {
		e.active(t, demoRef)
		id, err := e.st.SubmitOperation(ctx, demoRef, "restart", nil, 1, time.Now())
		must(t, err)
		must(t, e.st.StartOperation(ctx, id))
		must(t, e.st.BeginRestart(ctx, demoRef, 2, store.ProjectConfig{DiskQuotaMB: 1024, MemMB: 512}))
		must(t, e.st.FinishOperation(ctx, id, "failed", "internal: x"))
	}
	e := newEnv(t)
	strand(e)
	eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/abort", "", 409, "conflict")
	if !strings.Contains(eb.Message, "takes a new restart or a delete") {
		t.Errorf("abort: %q", eb.Message)
	}
	e.ops.used = 2300 << 20
	e.wantCode(t, "POST", pr, `{"disk_quota_mb":2048}`, 409, "quota_below_usage")
	e.wantOK(t, "POST", pr, `{"disk_quota_mb":8192}`, 202)
	var got restartShape
	strict(t, e.ops.params, &got)
	if got.BaseGeneration != 2 || got.Config.DiskQuotaMB != 8192 {
		t.Fatalf("takeover params %+v", got)
	}
	e.wantCode(t, "DELETE", "/v1/projects/"+demoRef, "", 409, "conflict") // the takeover is open

	e2 := newEnv(t)
	strand(e2)
	e2.wantOK(t, "DELETE", "/v1/projects/"+demoRef, "", 202)
}

// `project show` carries the bytes the user quota charges, beside the quota;
// null when they cannot be read or the project holds no directory. The list
// does not read them.
func TestAPI_ShowDiskUsed(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.ops.used = 2411724 << 10
	var p projectShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200), &p)
	if p.DiskUsedBytes == nil || *p.DiskUsedBytes != 2411724<<10 {
		t.Fatalf("disk_used_bytes %v", p.DiskUsedBytes)
	}
	e.ops.usedErr = errors.New("unreadable")
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200), &p)
	if p.DiskUsedBytes != nil {
		t.Fatalf("unreadable usage shown as %d", *p.DiskUsedBytes)
	}
	e.ops.usedErr = nil
	e.ops.usedUIDs = nil
	m := e.create(t, "")
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+m.Ref, "", 200), &p)
	b := e.wantOK(t, "GET", "/v1/projects", "", 200)
	if p.DiskUsedBytes != nil || len(e.ops.usedUIDs) != 0 || strings.Contains(string(b), "disk_used_bytes") {
		t.Fatalf("unplaced project %v, reads %v, list %s", p.DiskUsedBytes, e.ops.usedUIDs, b)
	}
}

// A quota tool that never returns does not hang `project show`: the usage
// read is bounded and the member is null.
func TestAPI_ShowDiskUsedBounded(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.ops.usedHang = true
	start := time.Now()
	var p projectShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200), &p)
	if d := time.Since(start); p.DiskUsedBytes != nil || d < showUsageWait || d > showUsageWait+3*time.Second {
		t.Fatalf("disk_used_bytes %v after %v", p.DiskUsedBytes, d)
	}
}

// A restart of a project in a state that takes no restart is refused for its
// state before any usage is read, whatever the quota.
func TestAPI_RestartStateBeforeUsage(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	must(t, e.st.SetProjectState(context.Background(), demoRef, "deleting"))
	e.ops.used = 1 << 40
	eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restart", `{"disk_quota_mb":2048}`, 409, "conflict")
	if !strings.Contains(eb.Message, "it is deleting") || len(e.ops.usedUIDs) != 0 {
		t.Fatalf("message %q, usage reads %v", eb.Message, e.ops.usedUIDs)
	}
}
