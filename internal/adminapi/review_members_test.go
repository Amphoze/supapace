package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/store"
)

// A cut-off is served while containment is unverified: a removal, a role
// that is lowered, a revocation and a rotation.
func TestReview_ContainmentUnverified_CutOffsServed(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	ctx := context.Background()
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "o", Role: "owner"}))
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "d", Role: "developer"}))
	e.ops.failed = true
	if m := e.member(t, "/members/remove", `{"subject":"o"}`, 200); m.ServiceKey != "rotated" || m.Generation == nil {
		t.Fatalf("%+v", m)
	}
	if m := e.member(t, "/members/role", `{"subject":"d","role":"read_only"}`, 200); strp(m.Role) != "read_only" {
		t.Fatalf("%+v", m)
	}
	e.wantOK(t, "POST", "/v1/dashboard/revocations", `{"subject":"o"}`, 200)
	e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/service-key/rotate", "", 200)
	_ = d
}

// Access is not widened while containment is unverified: an add and a role
// that is raised are refused before anything is changed.
// RED until the containment ruling of the review is applied.
func TestReview_ContainmentUnverified_GrantsRefused(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	ctx := context.Background()
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "r", Role: "read_only"}))
	e.ops.failed = true
	pushes := len(d.Calls())
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", `{"subject":"new","role":"owner"}`, 503, "containment_failed")
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/role", `{"subject":"r","role":"owner"}`, 503, "containment_failed")
	if e.role(t, dashIss, "new") != "" || e.role(t, dashIss, "r") != "read_only" || len(d.Calls()) != pushes {
		t.Fatalf("changed: %q", d.Calls())
	}
}

// An owner removed, the rotation committed and done, the push failed: the
// answer says the key was rotated and the file is not in force.
func TestReview_OwnerRemoved_RotatedButPushFails(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "o", Role: "owner"}))
	d.pushErr = errors.New("write: no space left on device")
	n := e.notInForce(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"o"}`)
	if n.ServiceKey != "rotated" || n.Rotation == nil || n.Rotation.Gateway != "done" || n.Generation != nil || n.StillValid != nil ||
		!strings.Contains(n.Message, "dashboard file: ") || strings.Contains(n.Message, "service-key rotation") {
		t.Fatalf("%+v", n)
	}
	if c := d.Calls(); len(c) < 2 || c[len(c)-2] != "rotate-member owner>" || c[len(c)-1] != "push" {
		t.Fatalf("%q", c)
	}
}

// A capability's error text reaches the answer cleaned and capped.
func TestReview_CapabilityError_CleanedAndCapped(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "r", Role: "read_only"}))
	d.jobsErr = errors.New("x\x1b[2J‮" + strings.Repeat("y", 4000))
	got, b := e.do(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"r"}`)
	if got != 503 || strings.Contains(string(b), `\u001b`) || strings.Contains(string(b), "‮") || len(b) > 4*maxMessage+1024 {
		t.Fatalf("%d %d %.200s", got, len(b), b)
	}
}

// Duplicate kids among the signing keys refuse the set; the stored issuer
// is unchanged.
func TestReview_Issuer_DuplicateKid_Unchanged(t *testing.T) {
	e := newEnv(t)
	e.withDash(t, "dprj")
	e.setIssuer(t)
	before, err := e.st.GetDashboardIssuer(context.Background())
	must(t, err)
	k0, k1 := dashKey(t, 0), dashKey(t, 1)
	e.wantCode(t, "PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[`+rsaEntry(k0, "x", "")+`,`+rsaEntry(k1, "x", "")+`]}`), 400, "bad_request")
	after, err := e.st.GetDashboardIssuer(context.Background())
	must(t, err)
	if string(after.JWKS) != string(before.JWKS) || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatal("changed")
	}
	// A body over the request bound is refused before the parser.
	e.wantCode(t, "PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[`+rsaEntry(k0, "a", `,"x":"`+strings.Repeat("a", 200<<10)+`"`)+`]}`), 413, "bad_request")
}

// An RSA entry whose key_ops allow no verification is an encryption key and
// never a sign-in key. RED: jwtx.ParseJWKS does not read key_ops.
func TestReview_Issuer_KeyOpsEncryptOnly_NotStored(t *testing.T) {
	e := newEnv(t)
	e.withDash(t, "dprj")
	set := `{"keys":[` + rsaEntry(dashKey(t, 0), "sig", "") + `,` + rsaEntry(dashKey(t, 1), "enc", `,"key_ops":["encrypt","wrapKey"]`) + `]}`
	var doc struct {
		Kids []string `json:"kids"`
	}
	b := e.wantOK(t, "PUT", "/v1/dashboard/issuer", issuerBody(set), 200)
	must(t, json.Unmarshal(b, &doc))
	if len(doc.Kids) != 1 || doc.Kids[0] != "sig" {
		t.Fatalf("stored kids %q", doc.Kids)
	}
}

// A file of newlines does not make the daemon allocate many times the read
// bound. RED: bytes.Split materialises one slice header per line.
func TestReview_Audit_NewlineFlood_BoundedMemory(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	dir := e.auditDir(t)
	must(t, os.WriteFile(filepath.Join(dir, "audit.log"), []byte(strings.Repeat("\n", 8<<20)), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "audit.log.1"), []byte(strings.Repeat("\n", 8<<20)), 0o600))
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	a := e.audit(t, "")
	runtime.ReadMemStats(&m1)
	if len(a.Records) != 0 {
		t.Fatalf("%+v", a)
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 64<<20 {
		t.Fatalf("one audit read of 16 MiB allocated %d MiB", alloc>>20)
	}
}

// in_force is never true without a file (generation 0), whatever the
// capability says.
func TestReview_DashboardShow_NoGenerationNeverInForce(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	d.mu.Lock()
	d.inForce, d.gen = true, 0
	d.mu.Unlock()
	var s dashShowJSON
	strict(t, e.wantOK(t, "GET", "/v1/dashboard", "", 200), &s)
	if s.InForce || s.Generation != nil {
		t.Fatalf("%+v", s)
	}
}

// A member write on an unknown project says so, not "not a member".
func TestReview_MemberWrite_UnknownProject(t *testing.T) {
	e := newEnv(t)
	e.withDash(t, "dprj")
	e.setIssuer(t)
	eb := e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/members/role", `{"subject":"a","role":"owner"}`, 404, "not_found")
	if eb.Message != "no such project" {
		t.Fatalf("%q", eb.Message)
	}
	eb = e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/members/remove", `{"subject":"a"}`, 404, "not_found")
	if eb.Message != "no such project" {
		t.Fatalf("%q", eb.Message)
	}
}

// A line holding a record and more after it is not a record.
func TestReview_Audit_TrailingDataSkipped(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	dir := e.auditDir(t)
	one := strings.TrimSuffix(auditLine("a"), "\n")
	must(t, os.WriteFile(filepath.Join(dir, "audit.log"), []byte(one+one+"\n"+one+` x`+"\n"+auditLine("b")), 0o600))
	if a := e.audit(t, ""); subs(a) != "b" || a.Skipped != 2 {
		t.Fatalf("%+v", a)
	}
}

// While containment is unverified a read_only membership that ends is
// committed and pushed, but the request opens no platform session to the
// cluster: the clean-up is left to the owed record, and the answer says so.
func TestReview_ContainmentUnverified_ReadOnlyEnds_NoCleanupInTheRequest(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	ctx := context.Background()
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "r", Role: "read_only"}))
	e.ops.failed = true
	n := e.notInForce(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"r"}`)
	if n.Generation == nil || !strings.HasPrefix(strp(n.Jobs), "not run: ") || !strings.Contains(n.Message, "containment") {
		t.Fatalf("%+v", n)
	}
	if e.role(t, dashIss, "r") != "" {
		t.Fatal("not committed")
	}
	if slices.Contains(d.Calls(), "jobs "+demoRef) {
		t.Fatalf("clean-up ran uncontained: %q", d.Calls())
	}
	// The manual trigger is refused too.
	got, b := e.do(t, "POST", "/v1/projects/"+demoRef+"/members/clean-jobs", "")
	if got == 200 || slices.Contains(d.Calls(), "jobs "+demoRef) {
		t.Fatalf("%d %s %q", got, b, d.Calls())
	}
	// The record is owed.
	rows, _, err := e.st.ReadOnlyCleanups(ctx, 10)
	must(t, err)
	if len(rows) != 1 || rows[0].Ref != demoRef {
		t.Fatalf("owed %+v", rows)
	}
}
