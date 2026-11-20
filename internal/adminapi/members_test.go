package adminapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/store"
)

// dash stands in for the daemon's dashboard capabilities. Each capability is
// a type of its own, so a test leaves one out by not embedding it.
type dash struct {
	st *store.Store

	mu         sync.Mutex
	domain     string
	calls      []string
	probe      func() string // appended to the push's call record
	pushErr    error
	pushZero   bool // the push answers generation 0 without an error
	gen        int64
	inForce    bool
	inForceErr error
	outcome    RotationOutcome
	rotErr     error // nothing committed
	jobsErr    error
}

func (d *dash) record(s string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, s)
}

func (d *dash) Calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.calls)
}

type domainCap struct{ d *dash }

func (c domainCap) StudioDomain() string { return c.d.domain }

type pushCap struct{ d *dash }

func (c pushCap) PushDashboard(context.Context) (int64, error) {
	d := c.d
	s := "push"
	if d.probe != nil {
		s += " " + d.probe()
	}
	d.record(s)
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.pushErr != nil:
		return 0, d.pushErr
	case d.pushZero:
		return 0, nil
	}
	d.gen++
	return d.gen, nil
}

func (c pushCap) DashboardInForce(context.Context) (int64, bool, error) {
	d := c.d
	d.record("inforce")
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gen, d.inForce, d.inForceErr
}

type rotCap struct{ d *dash }

func (c rotCap) ChangeMemberRotating(ctx context.Context, ref, issuer, subject, fromRole, toRole string) (RotationOutcome, error) {
	d := c.d
	d.record("rotate-member " + fromRole + ">" + toRole)
	if d.rotErr != nil {
		return RotationOutcome{}, d.rotErr
	}
	if err := d.st.ChangeMember(ctx, ref, issuer, subject, fromRole, toRole); err != nil {
		return RotationOutcome{}, err
	}
	return d.outcome, nil
}

func (c rotCap) RotateServiceKey(ctx context.Context, ref string) (RotationOutcome, error) {
	d := c.d
	d.record("rotate-key " + ref)
	if d.rotErr != nil {
		return RotationOutcome{}, d.rotErr
	}
	if _, err := d.st.GetProject(ctx, ref); err != nil {
		return RotationOutcome{}, err
	}
	return d.outcome, nil
}

type jobsCap struct{ d *dash }

func (c jobsCap) DropReadOnlyJobs(_ context.Context, ref string) error {
	c.d.record("jobs " + ref)
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	return c.d.jobsErr
}

// withDash replaces the env's handler with one whose Ops has the
// capabilities named in caps: d(omain), p(ush), r(otation), j(obs).
func (e *env) withDash(t *testing.T, caps string) *dash {
	t.Helper()
	d := &dash{st: e.st, domain: "studio.example.test", outcome: RotationOutcome{Gateway: "done", Rest: "done"}}
	var ops Ops
	switch caps {
	case "dprj":
		ops = struct {
			*fakeOps
			domainCap
			pushCap
			rotCap
			jobsCap
		}{e.ops, domainCap{d}, pushCap{d}, rotCap{d}, jobsCap{d}}
	case "prj":
		ops = struct {
			*fakeOps
			pushCap
			rotCap
			jobsCap
		}{e.ops, pushCap{d}, rotCap{d}, jobsCap{d}}
	case "drj":
		ops = struct {
			*fakeOps
			domainCap
			rotCap
			jobsCap
		}{e.ops, domainCap{d}, rotCap{d}, jobsCap{d}}
	case "dpj":
		ops = struct {
			*fakeOps
			domainCap
			pushCap
			jobsCap
		}{e.ops, domainCap{d}, pushCap{d}, jobsCap{d}}
	case "dpr":
		ops = struct {
			*fakeOps
			domainCap
			pushCap
			rotCap
		}{e.ops, domainCap{d}, pushCap{d}, rotCap{d}}
	default:
		t.Fatalf("withDash: %q", caps)
	}
	e.h = New(e.st, e.kek, ops, "sp.test", e.p)
	return d
}

// memberDocT is the member document, decoded strictly.
type memberDocT struct {
	Ref          string        `json:"ref"`
	Issuer       string        `json:"issuer"`
	Subject      string        `json:"subject"`
	Role         *string       `json:"role"`
	PreviousRole *string       `json:"previous_role"`
	ServiceKey   string        `json:"service_key"`
	Rotation     *rotationJSON `json:"rotation"`
	StillValid   *string       `json:"still_valid"`
	Jobs         *string       `json:"jobs"`
	Generation   *int64        `json:"dashboard_generation"`
}

// notInForceT is a 503 not_in_force answer: the error and the document.
type notInForceT struct {
	Code         string        `json:"code"`
	Message      string        `json:"message"`
	Ref          string        `json:"ref"`
	Issuer       string        `json:"issuer"`
	Subject      string        `json:"subject"`
	Role         *string       `json:"role"`
	PreviousRole *string       `json:"previous_role"`
	ServiceKey   string        `json:"service_key"`
	Rotation     *rotationJSON `json:"rotation"`
	StillValid   *string       `json:"still_valid"`
	Jobs         *string       `json:"jobs"`
	Generation   *int64        `json:"dashboard_generation"`
}

const dashIss = "https://id.example.test"

var (
	dashKeyOnce sync.Once
	dashKeys    [2]jwtx.Key
)

// dashKey is one of two generated RSA keys, neither of them a project's.
func dashKey(t *testing.T, i int) jwtx.Key {
	t.Helper()
	dashKeyOnce.Do(func() {
		for j := range dashKeys {
			priv, kid, err := jwtx.GenerateKey()
			if err != nil {
				panic(err)
			}
			dashKeys[j] = jwtx.Key{KID: kid, Class: jwtx.ClassDashboard, Pub: &priv.PublicKey}
		}
	})
	return dashKeys[i]
}

func b64n(k jwtx.Key) string { return base64.RawURLEncoding.EncodeToString(k.Pub.N.Bytes()) }

// rsaEntry is one RSA entry of a key set with the given extra members.
func rsaEntry(k jwtx.Key, kid, extra string) string {
	return fmt.Sprintf(`{"kty":"RSA","kid":%q,"n":%q,"e":"AQAB"%s}`, kid, b64n(k), extra)
}

func issuerBody(jwks string) string {
	return `{"issuer":"` + dashIss + `","client_id":"studio","authorize_url":"https://id.example.test/authorize",` +
		`"end_session_url":"https://id.example.test/logout","session_seconds":3600,"jwks":` + jwks + `}`
}

func (e *env) setIssuer(t *testing.T) {
	t.Helper()
	e.wantOK(t, "PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[`+rsaEntry(dashKey(t, 0), "d0", "")+`]}`), 200)
}

// member posts a member write and decodes the answer as a document.
func (e *env) member(t *testing.T, path, body string, status int) memberDocT {
	t.Helper()
	var m memberDocT
	strict(t, e.wantOK(t, "POST", "/v1/projects/"+demoRef+path, body, status), &m)
	return m
}

func (e *env) notInForce(t *testing.T, method, path, body string) notInForceT {
	t.Helper()
	got, b := e.do(t, method, path, body)
	var n notInForceT
	strict(t, b, &n)
	if got != http.StatusServiceUnavailable || n.Code != "not_in_force" || !strings.HasPrefix(n.Message, "committed; not yet in force: ") {
		t.Fatalf("%s %s: %d %s, want 503 not_in_force", method, path, got, b)
	}
	return n
}

func ptr(s string) *string { return &s }

func strp(p *string) string {
	if p == nil {
		return "<null>"
	}
	return *p
}

func (e *env) role(t *testing.T, iss, sub string) string {
	t.Helper()
	r, err := e.st.MemberRole(context.Background(), demoRef, iss, sub)
	if errors.Is(err, store.ErrNotFound) {
		return ""
	}
	must(t, err)
	return r
}

func TestMembers_AddListRoleRemove_Documents(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)

	m := e.member(t, "/members", `{"subject":"alice","role":"developer"}`, 200)
	want := memberDocT{Ref: demoRef, Issuer: dashIss, Subject: "alice", Role: ptr("developer"), ServiceKey: "unchanged"}
	if m.Generation == nil || *m.Generation <= 0 {
		t.Fatalf("add: generation %v", m.Generation)
	}
	m.Generation = nil
	if g, w := mustJSON(t, m), mustJSON(t, want); g != w {
		t.Fatalf("add: %+v, want %+v", m, want)
	}
	e.member(t, "/members", `{"issuer":"https://other.example.test","subject":"bob","role":"read_only"}`, 200)

	var l struct {
		Ref     string `json:"ref"`
		Members []struct {
			Issuer  string `json:"issuer"`
			Subject string `json:"subject"`
			Role    string `json:"role"`
			AddedAt string `json:"added_at"`
		} `json:"members"`
	}
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/members", "", 200), &l)
	if l.Ref != demoRef || len(l.Members) != 2 || l.Members[0].Subject != "alice" || l.Members[0].Role != "developer" ||
		l.Members[1].Issuer != "https://other.example.test" || l.Members[1].Role != "read_only" {
		t.Fatalf("list: %+v", l)
	}
	if _, err := time.Parse(time.RFC3339, l.Members[0].AddedAt); err != nil || !strings.HasSuffix(l.Members[0].AddedAt, "Z") {
		t.Fatalf("added_at %q", l.Members[0].AddedAt)
	}

	m = e.member(t, "/members/role", `{"subject":"alice","role":"owner"}`, 200)
	if strp(m.Role) != "owner" || strp(m.PreviousRole) != "developer" || m.ServiceKey != "unchanged" || m.Rotation != nil || m.Jobs != nil {
		t.Fatalf("set-role: %+v", m)
	}
	m = e.member(t, "/members/remove", `{"subject":"alice","service_key":"keep"}`, 200)
	if m.Role != nil || strp(m.PreviousRole) != "owner" || m.ServiceKey != "kept" || m.StillValid == nil ||
		!strings.Contains(*m.StillValid, "rotate-key "+demoRef+" --service") {
		t.Fatalf("remove: %+v", m)
	}
	if e.role(t, dashIss, "alice") != "" {
		t.Fatal("alice is still a member")
	}
	// Every write pushed; nothing rotated or cleaned.
	for _, c := range d.Calls() {
		if c != "push" {
			t.Fatalf("calls %q", d.Calls())
		}
	}
	// An empty project lists [] and a project that does not exist is not found.
	e.member(t, "/members/remove", `{"issuer":"https://other.example.test","subject":"bob"}`, 200)
	if b := e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/members", "", 200); !strings.Contains(string(b), `"members":[]`) {
		t.Fatalf("empty list: %s", b)
	}
	e.wantCode(t, "GET", "/v1/projects/zzzz0000000000000000/members", "", 404, "not_found")
	e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/members", `{"subject":"x","role":"owner"}`, 404, "not_found")
	eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/role", `{"subject":"nobody","role":"owner"}`, 404, "not_found")
	if !strings.Contains(eb.Message, "not a member") {
		t.Fatalf("unknown member: %q", eb.Message)
	}
	// Refusals before the store: role, service_key, unknown members, case.
	for _, b := range []string{
		`{"subject":"x","role":"admin"}`, `{"subject":"x"}`, `{"subject":"x","role":"owner","service_key":"keep"}`,
		`{"subject":"x","role":"owner","Role":"owner"}`, `{"subject":"x","subject":"y","role":"owner"}`,
	} {
		e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", b, 400, "bad_request")
	}
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"x","service_key":"later"}`, 400, "bad_request")
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/role", `{"subject":"x"}`, 400, "bad_request")
	e.wantCode(t, "POST", "/v1/projects/BAD/members", `{"subject":"x","role":"owner"}`, 400, "bad_ref")
	// A member of a deleted project cannot be added: the store's state rule.
	e.deleted(t, demoRef)
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", `{"subject":"x","role":"owner"}`, 409, "conflict")
}

func TestMembers_PrincipalInTheBodyOnly(t *testing.T) {
	e := newEnv(t)
	e.withDash(t, "dprj")
	e.active(t, demoRef)
	sub := "user/with?query=1&x#frag"
	m := e.member(t, "/members", `{"issuer":"https://id.example.test/tenant?x=1","subject":"`+sub+`","role":"developer"}`, 200)
	if m.Subject != sub || m.Issuer != "https://id.example.test/tenant?x=1" {
		t.Fatalf("add: %+v", m)
	}
	if e.role(t, "https://id.example.test/tenant?x=1", sub) != "developer" {
		t.Fatal("not stored")
	}
	m = e.member(t, "/members/remove", `{"issuer":"https://id.example.test/tenant?x=1","subject":"`+sub+`"}`, 200)
	if m.Role != nil || strp(m.PreviousRole) != "developer" {
		t.Fatalf("remove: %+v", m)
	}
	// No route takes a principal in its path.
	for _, p := range []string{"/members/alice", "/members/user%2Fx", "/members/alice/remove", "/members/https%3A%2F%2Fid/alice"} {
		for _, method := range []string{"GET", "POST", "DELETE", "PUT"} {
			e.wantCode(t, method, "/v1/projects/"+demoRef+p, "", 404, "not_found")
		}
	}
	// Not printable ASCII, empty, too long: refused before the store.
	for _, s := range []string{"", strings.Repeat("a", 256), "a‮b", "tab\there", "bell\u0007"} {
		b, _ := json.Marshal(map[string]string{"subject": s, "role": "owner", "issuer": dashIss})
		eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", string(b), 400, "bad_request")
		if strings.Contains(eb.Message, s) && s != "" {
			t.Fatalf("the refusal echoes the subject: %q", eb.Message)
		}
	}
	b, _ := json.Marshal(map[string]string{"subject": "ok", "role": "owner", "issuer": "x\u0000y"})
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", string(b), 400, "bad_request")
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", `{"subject":"ok","role":"owner","issuer":""}`, 400, "bad_request")
	// 255 bytes pass.
	long := strings.Repeat("s", 255)
	e.member(t, "/members", `{"issuer":"`+dashIss+`","subject":"`+long+`","role":"owner"}`, 200)
}

func TestMembers_IssuerDefaultsToTheConfigured(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	// No issuer set and none named: refused before anything changes.
	eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", `{"subject":"alice","role":"owner"}`, 409, "conflict")
	if !strings.Contains(eb.Message, "supapace dashboard issuer set") {
		t.Fatalf("message %q", eb.Message)
	}
	e.wantCode(t, "POST", "/v1/dashboard/revocations", `{"subject":"alice"}`, 409, "conflict")
	if len(d.Calls()) != 0 {
		t.Fatalf("calls %q", d.Calls())
	}
	// Named, it is taken as given.
	e.member(t, "/members", `{"issuer":"https://elsewhere.example.test","subject":"alice","role":"owner"}`, 200)
	e.setIssuer(t)
	m := e.member(t, "/members", `{"subject":"alice","role":"owner"}`, 200)
	if m.Issuer != dashIss || e.role(t, dashIss, "alice") != "owner" || e.role(t, "https://elsewhere.example.test", "alice") != "owner" {
		t.Fatalf("default issuer: %+v", m)
	}
	m = e.member(t, "/members/role", `{"subject":"alice","role":"developer","service_key":"keep"}`, 200)
	if m.Issuer != dashIss || strp(m.PreviousRole) != "owner" {
		t.Fatalf("role: %+v", m)
	}
}

func TestMembers_NoStudioDomain_Conflict(t *testing.T) {
	for _, caps := range []string{"prj", "dprj"} { // the capability absent; present with an empty answer
		t.Run(caps, func(t *testing.T) {
			e := newEnv(t)
			d := e.withDash(t, caps)
			d.domain = ""
			e.active(t, demoRef)
			must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "a", Role: "owner"}))
			p := "/v1/projects/" + demoRef
			for _, c := range []struct{ method, path, body string }{
				{"GET", p + "/members", ""},
				{"POST", p + "/members", `{"issuer":"` + dashIss + `","subject":"b","role":"owner"}`},
				{"POST", p + "/members/role", `{"issuer":"` + dashIss + `","subject":"a","role":"developer"}`},
				{"POST", p + "/members/remove", `{"issuer":"` + dashIss + `","subject":"a"}`},
				{"POST", p + "/members/clean-jobs", ""},
				{"GET", "/v1/dashboard/issuer", ""},
				{"PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[` + rsaEntry(dashKey(t, 0), "d0", "") + `]}`)},
				{"POST", "/v1/dashboard/revocations", `{"issuer":"` + dashIss + `","subject":"a"}`},
				{"GET", "/v1/dashboard", ""},
			} {
				eb := e.wantCode(t, c.method, c.path, c.body, 409, "conflict")
				if !strings.HasPrefix(eb.Message, "this node has no studio domain") {
					t.Fatalf("%s %s: %q", c.method, c.path, eb.Message)
				}
			}
			if e.role(t, dashIss, "a") != "owner" || len(d.Calls()) != 0 {
				t.Fatalf("changed: calls %q", d.Calls())
			}
			// The two routes that are static for every node.
			e.wantOK(t, "GET", p+"/audit", "", 200)
			var r struct {
				Ref        string        `json:"ref"`
				ServiceKey string        `json:"service_key"`
				Rotation   *rotationJSON `json:"rotation"`
			}
			strict(t, e.wantOK(t, "POST", p+"/service-key/rotate", "", 200), &r)
			if r.Ref != demoRef || r.ServiceKey != "rotated" || r.Rotation == nil || r.Rotation.Gateway != "done" {
				t.Fatalf("rotate: %+v", r)
			}
		})
	}
}

func TestMembers_RotationDecision(t *testing.T) {
	for _, c := range []struct {
		name, from, path, body string
		rotated                bool
		serviceKey             string
	}{
		{"owner removed", "owner", "/members/remove", `{"subject":"a"}`, true, "rotated"},
		{"owner removed, default named", "owner", "/members/remove", `{"subject":"a","service_key":"default"}`, true, "rotated"},
		{"owner removed, kept", "owner", "/members/remove", `{"subject":"a","service_key":"keep"}`, false, "kept"},
		{"owner to developer", "owner", "/members/role", `{"subject":"a","role":"developer"}`, true, "rotated"},
		{"owner to read_only, kept", "owner", "/members/role", `{"subject":"a","role":"read_only","service_key":"keep"}`, false, "kept"},
		{"developer removed", "developer", "/members/remove", `{"subject":"a"}`, false, "unchanged"},
		{"developer removed, rotate", "developer", "/members/remove", `{"subject":"a","service_key":"rotate"}`, true, "rotated"},
		{"developer to owner", "developer", "/members/role", `{"subject":"a","role":"owner"}`, false, "unchanged"},
		{"owner stays owner", "owner", "/members/role", `{"subject":"a","role":"owner"}`, false, "unchanged"},
		{"owner stays owner, default named", "owner", "/members/role", `{"subject":"a","role":"owner","service_key":"default"}`, false, "unchanged"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			d := e.withDash(t, "dprj")
			e.active(t, demoRef)
			e.setIssuer(t)
			must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "a", Role: c.from}))
			m := e.member(t, c.path, c.body, 200)
			rotatedCall := slices.ContainsFunc(d.Calls(), func(s string) bool { return strings.HasPrefix(s, "rotate-member ") })
			if rotatedCall != c.rotated || m.ServiceKey != c.serviceKey || (m.Rotation != nil) != c.rotated ||
				(m.StillValid != nil) != (c.serviceKey == "kept") {
				t.Fatalf("calls %q, doc %+v", d.Calls(), m)
			}
		})
	}
	// An owner who stays an owner never rotates: asked to, it is refused.
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "a", Role: "owner"}))
	eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/role", `{"subject":"a","role":"owner","service_key":"rotate"}`, 400, "bad_request")
	if !strings.Contains(eb.Message, "supapace project rotate-key "+demoRef+" --service") || slices.Contains(d.Calls(), "rotate-member owner>owner") {
		t.Fatalf("%q %q", eb.Message, d.Calls())
	}
}

func TestMembers_RotationUnavailable_ConflictAndNothingChanged(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dpj")
	e.active(t, demoRef)
	e.setIssuer(t)
	ctx := context.Background()
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "o", Role: "owner"}))
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "dev", Role: "developer"}))
	before := len(d.Calls())
	for _, c := range []struct{ path, body string }{
		{"/members/remove", `{"subject":"o"}`},
		{"/members/role", `{"subject":"o","role":"developer"}`},
		{"/members/remove", `{"subject":"dev","service_key":"rotate"}`},
	} {
		eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+c.path, c.body, 409, "conflict")
		if eb.Message != "service-key rotation is not available in this daemon; repeat with the service key kept (--keep-service-key)" {
			t.Fatalf("%q", eb.Message)
		}
	}
	eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/service-key/rotate", "", 409, "conflict")
	if !strings.HasPrefix(eb.Message, "service-key rotation is not available in this daemon") {
		t.Fatalf("%q", eb.Message)
	}
	if e.role(t, dashIss, "o") != "owner" || e.role(t, dashIss, "dev") != "developer" || len(d.Calls()) != before {
		t.Fatalf("changed: %q", d.Calls())
	}
	// Kept, the removal goes through.
	if m := e.member(t, "/members/remove", `{"subject":"o","service_key":"keep"}`, 200); m.ServiceKey != "kept" {
		t.Fatalf("%+v", m)
	}
	// A rotation that fails before its commit changes nothing and answers its error.
	e2 := newEnv(t)
	d2 := e2.withDash(t, "dprj")
	e2.active(t, demoRef)
	e2.setIssuer(t)
	must(t, e2.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "o", Role: "owner"}))
	d2.rotErr = fmt.Errorf("%w: the project's service_role key changed meanwhile", store.ErrConflict)
	e2.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"o"}`, 409, "conflict")
	if e2.role(t, dashIss, "o") != "owner" || !slices.Equal(d2.Calls(), []string{"push", "rotate-member owner>"}) {
		t.Fatalf("calls %q", d2.Calls())
	}
}

func TestMembers_ReadOnlyEnds_JobsCleanedAfterThePush(t *testing.T) {
	for _, c := range []struct {
		name, from, path, body string
		jobs                   bool
	}{
		{"read_only removed", "read_only", "/members/remove", `{"subject":"r"}`, true},
		{"read_only to developer", "read_only", "/members/role", `{"subject":"r","role":"developer"}`, true},
		{"developer removed", "developer", "/members/remove", `{"subject":"r"}`, false},
		{"developer to read_only", "developer", "/members/role", `{"subject":"r","role":"read_only"}`, false},
		{"read_only stays read_only", "read_only", "/members/role", `{"subject":"r","role":"read_only"}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			d := e.withDash(t, "dprj")
			e.active(t, demoRef)
			e.setIssuer(t)
			must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "r", Role: c.from}))
			start := len(d.Calls())
			d.probe = func() string { return "role=" + e.role(t, dashIss, "r") }
			m := e.member(t, c.path, c.body, 200)
			after := m.Role
			wantRole := ""
			if after != nil {
				wantRole = *after
			}
			got := d.Calls()[start:]
			if c.jobs {
				want := []string{"push role=" + wantRole, "jobs " + demoRef}
				if !slices.Equal(got, want) || strp(m.Jobs) != "ran" {
					t.Fatalf("calls %q (want %q), jobs %s", got, want, strp(m.Jobs))
				}
			} else if !slices.Equal(got, []string{"push role=" + wantRole}) || m.Jobs != nil {
				t.Fatalf("calls %q, jobs %s", got, strp(m.Jobs))
			}
			// "ran" carries no count.
			if b := e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/members", "", 200); strings.Contains(string(b), "jobs") {
				t.Fatalf("%s", b)
			}
		})
	}
}

func TestMembers_JobsCleanupFails_NotInForceAndCommitted(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "r", Role: "read_only"}))
	d.jobsErr = errors.New("lock timeout on the scheduled-job table")
	n := e.notInForce(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"r"}`)
	if strp(n.Jobs) != "failed: lock timeout on the scheduled-job table" || n.Generation == nil || n.Role != nil ||
		strp(n.PreviousRole) != "read_only" || !strings.Contains(n.Message, "read-only clean-up: lock timeout") {
		t.Fatalf("%+v", n)
	}
	if e.role(t, dashIss, "r") != "" {
		t.Fatal("the row is still there")
	}
	// Repeated, the request finds the change made.
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"r"}`, 404, "not_found")
}

func TestMembers_NoJobsCapability_RefusedBeforeAnyWrite(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dpr")
	e.active(t, demoRef)
	e.setIssuer(t)
	ctx := context.Background()
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "r", Role: "read_only"}))
	start := len(d.Calls())
	for _, c := range []struct{ path, body string }{
		{"/members/remove", `{"subject":"r"}`},
		{"/members/role", `{"subject":"r","role":"owner"}`},
	} {
		eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+c.path, c.body, 409, "conflict")
		if !strings.Contains(eb.Message, "scheduled jobs") {
			t.Fatalf("%q", eb.Message)
		}
	}
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/clean-jobs", "", 409, "conflict")
	if e.role(t, dashIss, "r") != "read_only" || len(d.Calls()) != start {
		t.Fatalf("changed: %q", d.Calls()[start:])
	}
	// What does not end a read_only membership needs no clean-up.
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "dev", Role: "developer"}))
	e.member(t, "/members/remove", `{"subject":"dev"}`, 200)
}

func TestMembers_CleanJobs_Route(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "r", Role: "read_only"}))
	p := "/v1/projects/" + demoRef + "/members/clean-jobs"
	type doc struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Ref     string `json:"ref"`
		Jobs    string `json:"jobs"`
	}
	// Not in force: not run.
	start := len(d.Calls())
	got, b := e.do(t, "POST", p, "")
	var r doc
	strict(t, b, &r)
	if got != 503 || r.Code != "not_in_force" || r.Jobs != "not run: dashboard not in force" ||
		!slices.Equal(d.Calls()[start:], []string{"inforce"}) {
		t.Fatalf("%d %+v %q", got, r, d.Calls()[start:])
	}
	// In force: run.
	d.inForce, d.gen = true, 7
	start = len(d.Calls())
	r = doc{}
	strict(t, e.wantOK(t, "POST", p, "", 200), &r)
	if r.Ref != demoRef || r.Jobs != "ran" || r.Code != "" || !slices.Equal(d.Calls()[start:], []string{"inforce", "jobs " + demoRef}) {
		t.Fatalf("%+v %q", r, d.Calls()[start:])
	}
	if e.role(t, dashIss, "r") != "read_only" {
		t.Fatal("a member changed")
	}
	// A failed run.
	d.jobsErr = errors.New("the cluster did not answer")
	r = doc{}
	got, b = e.do(t, "POST", p, "")
	strict(t, b, &r)
	if got != 503 || r.Code != "not_in_force" || r.Jobs != "failed: the cluster did not answer" {
		t.Fatalf("%d %s", got, b)
	}
	e.wantCode(t, "POST", p, `{}`, 400, "bad_request")
	e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/members/clean-jobs", "", 404, "not_found")
	e.deleted(t, demoRef)
	e.wantCode(t, "POST", p, "", 409, "conflict")
}

func TestMembers_PushFails_NotInForceAndCommitted(t *testing.T) {
	for _, zero := range []bool{false, true} {
		t.Run(fmt.Sprint("zero=", zero), func(t *testing.T) {
			e := newEnv(t)
			d := e.withDash(t, "dprj")
			e.active(t, demoRef)
			e.setIssuer(t)
			ctx := context.Background()
			must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "d", Role: "developer"}))
			must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "r", Role: "read_only"}))
			if zero {
				d.pushZero = true
			} else {
				d.pushErr = errors.New("rename: no space left on device")
			}
			n := e.notInForce(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"d"}`)
			if n.Generation != nil || n.Role != nil || strp(n.PreviousRole) != "developer" || n.Jobs != nil ||
				!strings.HasPrefix(n.Message, "committed; not yet in force: dashboard file: ") {
				t.Fatalf("%+v", n)
			}
			if !zero && !strings.Contains(n.Message, "no space left on device") {
				t.Fatalf("%q", n.Message)
			}
			if e.role(t, dashIss, "d") != "" {
				t.Fatal("the row is still there")
			}
			e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"d"}`, 404, "not_found")
			// A read_only removal: the clean-up is not attempted.
			n = e.notInForce(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"r"}`)
			if strp(n.Jobs) != "not run: dashboard not in force" || slices.Contains(d.Calls(), "jobs "+demoRef) {
				t.Fatalf("%+v %q", n, d.Calls())
			}
			// Adds, issuer and revocations answer the same way.
			n = e.notInForce(t, "POST", "/v1/projects/"+demoRef+"/members", `{"subject":"new","role":"owner"}`)
			if e.role(t, dashIss, "new") != "owner" || strp(n.Role) != "owner" {
				t.Fatalf("%+v", n)
			}
			got, b := e.do(t, "POST", "/v1/dashboard/revocations", `{"subject":"new"}`)
			if got != 503 || !strings.Contains(string(b), `"dashboard_generation":null`) || !strings.Contains(string(b), `"not_in_force"`) {
				t.Fatalf("%d %s", got, b)
			}
			got, b = e.do(t, "PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[`+rsaEntry(dashKey(t, 1), "d1", "")+`]}`))
			if got != 503 || !strings.Contains(string(b), `"kids":["d1"]`) {
				t.Fatalf("%d %s", got, b)
			}
		})
	}
}

func TestMembers_NoPusher_RefusedBeforeAnyWrite(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "drj")
	e.active(t, demoRef)
	ctx := context.Background()
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "a", Role: "developer"}))
	p := "/v1/projects/" + demoRef
	for _, c := range []struct{ method, path, body string }{
		{"POST", p + "/members", `{"issuer":"` + dashIss + `","subject":"b","role":"owner"}`},
		{"POST", p + "/members/role", `{"issuer":"` + dashIss + `","subject":"a","role":"owner"}`},
		{"POST", p + "/members/remove", `{"issuer":"` + dashIss + `","subject":"a"}`},
		{"PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[` + rsaEntry(dashKey(t, 0), "d0", "") + `]}`)},
		{"POST", "/v1/dashboard/revocations", `{"issuer":"` + dashIss + `","subject":"a"}`},
	} {
		eb := e.wantCode(t, c.method, c.path, c.body, 409, "conflict")
		if !strings.Contains(eb.Message, "cannot bring") {
			t.Fatalf("%s %s: %q", c.method, c.path, eb.Message)
		}
	}
	ms, err := e.st.ListMembers(ctx, demoRef)
	must(t, err)
	_, ierr := e.st.GetDashboardIssuer(ctx)
	tbl, err := e.st.DashboardTable(ctx)
	must(t, err)
	if len(ms) != 1 || ms[0].Role != "developer" || !errors.Is(ierr, store.ErrNotFound) || len(tbl.Revoked) != 0 || len(d.Calls()) != 0 {
		t.Fatalf("changed: %+v %v %+v %q", ms, ierr, tbl.Revoked, d.Calls())
	}
	// Reads are served; show says the file cannot be written.
	e.wantOK(t, "GET", p+"/members", "", 200)
	e.wantCode(t, "GET", "/v1/dashboard", "", 409, "conflict")
}

func TestMembers_RotationStepFails_NotInForce(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	must(t, e.st.AddMember(context.Background(), store.Member{Ref: demoRef, Issuer: dashIss, Subject: "o", Role: "owner"}))
	d.outcome = RotationOutcome{Gateway: "done", Rest: "failed: key-set file: permission denied", Err: errors.New("rest: key-set file: permission denied")}
	n := e.notInForce(t, "POST", "/v1/projects/"+demoRef+"/members/remove", `{"subject":"o"}`)
	if n.Rotation == nil || n.Rotation.Gateway != "done" || n.Rotation.Rest != "failed: key-set file: permission denied" ||
		n.ServiceKey != "rotated" || n.Generation == nil || !strings.Contains(n.Message, "service-key rotation: rest: key-set file") {
		t.Fatalf("%+v", n)
	}
	if e.role(t, dashIss, "o") != "" {
		t.Fatal("not committed")
	}
	// The project's own rotation answers the same way.
	got, b := e.do(t, "POST", "/v1/projects/"+demoRef+"/service-key/rotate", "")
	if got != 503 || !strings.Contains(string(b), `"rest":"failed: key-set file: permission denied"`) || !strings.Contains(string(b), `"not_in_force"`) {
		t.Fatalf("%d %s", got, b)
	}
	// An owed signal is a 200.
	d.outcome = RotationOutcome{Gateway: "done", Rest: "owed: signal follows"}
	var r struct {
		Ref        string        `json:"ref"`
		ServiceKey string        `json:"service_key"`
		Rotation   *rotationJSON `json:"rotation"`
	}
	strict(t, e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/service-key/rotate", "", 200), &r)
	if r.Rotation.Rest != "owed: signal follows" {
		t.Fatalf("%+v", r)
	}
	e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/service-key/rotate", "", 404, "not_found")
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/service-key/rotate", "{}", 400, "bad_request")
}

func TestMembers_CapRefused_Conflict(t *testing.T) {
	e := newEnv(t)
	e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	ctx := context.Background()
	for i := range 256 {
		must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: fmt.Sprint("m", i), Role: "developer"}))
	}
	eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", `{"subject":"one-more","role":"developer"}`, 409, "conflict")
	if eb.Message != "the project has the most members a dashboard file carries (256)" {
		t.Fatalf("%q", eb.Message)
	}
	eb = e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members", `{"subject":"m1","role":"owner"}`, 409, "conflict")
	if eb.Message != "the principal is already a member" {
		t.Fatalf("%q", eb.Message)
	}
}

func TestIssuer_SetShow_Validation(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.wantCode(t, "GET", "/v1/dashboard/issuer", "", 404, "not_found")
	k0, k1 := dashKey(t, 0), dashKey(t, 1)
	good := `{"keys":[` + rsaEntry(k0, "d0", "") + `]}`
	type issuerDocT struct {
		Issuer         string   `json:"issuer"`
		ClientID       string   `json:"client_id"`
		AuthorizeURL   string   `json:"authorize_url"`
		EndSessionURL  string   `json:"end_session_url"`
		SessionSeconds int      `json:"session_seconds"`
		Kids           []string `json:"kids"`
		UpdatedAt      string   `json:"updated_at"`
		Generation     *int64   `json:"dashboard_generation"`
	}
	var doc issuerDocT
	strict(t, e.wantOK(t, "PUT", "/v1/dashboard/issuer", issuerBody(good), 200), &doc)
	if doc.Issuer != dashIss || doc.ClientID != "studio" || doc.SessionSeconds != 3600 || !slices.Equal(doc.Kids, []string{"d0"}) ||
		doc.EndSessionURL != "https://id.example.test/logout" || doc.Generation == nil || !strings.HasSuffix(doc.UpdatedAt, "Z") {
		t.Fatalf("%+v", doc)
	}
	var shown issuerDocT
	strict(t, e.wantOK(t, "GET", "/v1/dashboard/issuer", "", 200), &shown)
	doc.Generation = nil
	if mustJSON(t, shown) != mustJSON(t, doc) {
		t.Fatalf("show %+v, set %+v", shown, doc)
	}
	// session_seconds defaults to the longest; end_session_url may be empty.
	strict(t, e.wantOK(t, "PUT", "/v1/dashboard/issuer", `{"issuer":"`+dashIss+`","client_id":"c","authorize_url":"https://id.example.test/a","jwks":`+good+`}`, 200), &doc)
	if doc.SessionSeconds != 28800 || doc.EndSessionURL != "" {
		t.Fatalf("%+v", doc)
	}

	// A mixed set: only the RSA signing keys are stored, re-encoded.
	ec := `{"kty":"EC","kid":"ec","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`
	mixed := `{"keys":[` + ec + `,` + rsaEntry(k1, "enc", `,"use":"enc"`) + `,` + rsaEntry(k0, "sig", `,"use":"sig","alg":"RS256","x5t":"abc"`) +
		`,` + rsaEntry(k1, "ps", `,"alg":"PS256"`) + `]}`
	strict(t, e.wantOK(t, "PUT", "/v1/dashboard/issuer", issuerBody(mixed), 200), &doc)
	if !slices.Equal(doc.Kids, []string{"sig"}) {
		t.Fatalf("kids %q", doc.Kids)
	}
	is, err := e.st.GetDashboardIssuer(context.Background())
	must(t, err)
	var stored struct{ Keys []map[string]any }
	must(t, json.Unmarshal(is.JWKS, &stored))
	if len(stored.Keys) != 1 || stored.Keys[0]["kid"] != "sig" || stored.Keys[0]["n"] != b64n(k0) || stored.Keys[0]["x5t"] != nil {
		t.Fatalf("stored %s", is.JWKS)
	}
	// An encryption key alone is never stored.
	before := is.JWKS
	e.wantCode(t, "PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[`+rsaEntry(k1, "enc", `,"use":"enc"`)+`]}`), 400, "bad_request")
	is, _ = e.st.GetDashboardIssuer(context.Background())
	if string(is.JWKS) != string(before) {
		t.Fatalf("stored %s", is.JWKS)
	}

	// A project's issuer key is refused (stored as the create's step stores it).
	e.create(t, demoRef)
	proj := issuerKey(t)
	set, err := jwtx.MarshalJWKS([]jwtx.Key{proj})
	must(t, err)
	var one struct{ Keys []json.RawMessage }
	must(t, json.Unmarshal(set, &one))
	must(t, e.st.PutKey(context.Background(), store.KeyRow{Ref: demoRef, KID: proj.KID, Class: "issuer", JWK: one.Keys[0]}))
	eb := e.wantCode(t, "PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[`+rsaEntry(k0, "a", "")+`,`+rsaEntry(proj, "p", "")+`]}`), 400, "bad_request")
	if !strings.Contains(eb.Message, "project") {
		t.Fatalf("%q", eb.Message)
	}

	var seventeen []string
	for i := range 17 {
		seventeen = append(seventeen, rsaEntry(k0, fmt.Sprint("k", i), ""))
	}
	var sixteen = slices.Clone(seventeen[:16])
	refused := map[string]string{
		"plain http":           strings.Replace(issuerBody(good), `"https://id.example.test/authorize"`, `"http://id.example.test/authorize"`, 1),
		"fragment":             strings.Replace(issuerBody(good), `"https://id.example.test/authorize"`, `"https://id.example.test/authorize#x"`, 1),
		"empty fragment":       strings.Replace(issuerBody(good), `"https://id.example.test/authorize"`, `"https://id.example.test/authorize#"`, 1),
		"end session http":     strings.Replace(issuerBody(good), `"https://id.example.test/logout"`, `"http://id.example.test/logout"`, 1),
		"end session fragment": strings.Replace(issuerBody(good), `"https://id.example.test/logout"`, `"https://id.example.test/logout#f"`, 1),
		"no host":              strings.Replace(issuerBody(good), `"https://id.example.test/authorize"`, `"https:///authorize"`, 1),
		"user info":            strings.Replace(issuerBody(good), `"https://id.example.test/authorize"`, `"https://u:p@127.0.0.1/authorize"`, 1),
		"url too long":         strings.Replace(issuerBody(good), `"https://id.example.test/authorize"`, `"https://id.example.test/`+strings.Repeat("a", 2048)+`"`, 1),
		"no usable key":        issuerBody(`{"keys":[` + ec + `]}`),
		"no keys":              issuerBody(`{"keys":[]}`),
		"private member":       issuerBody(`{"keys":[` + rsaEntry(k0, "d0", `,"d":"AQAB"`) + `]}`),
		"private in a skipped": issuerBody(`{"keys":[` + rsaEntry(k0, "d0", "") + `,` + rsaEntry(k1, "e", `,"use":"enc","d":"AQAB"`) + `]}`),
		"seventeen keys":       issuerBody(`{"keys":[` + strings.Join(seventeen, ",") + `]}`),
		"kid too long":         issuerBody(`{"keys":[` + rsaEntry(k0, strings.Repeat("k", 256), "") + `]}`),
		"issuer empty":         strings.Replace(issuerBody(good), `"issuer":"`+dashIss+`"`, `"issuer":""`, 1),
		"issuer control":       strings.Replace(issuerBody(good), `"issuer":"`+dashIss+`"`, `"issuer":"a\u001bb"`, 1),
		"client empty":         strings.Replace(issuerBody(good), `"client_id":"studio"`, `"client_id":""`, 1),
		"client too long":      strings.Replace(issuerBody(good), `"client_id":"studio"`, `"client_id":"`+strings.Repeat("c", 256)+`"`, 1),
		"session short":        strings.Replace(issuerBody(good), `"session_seconds":3600`, `"session_seconds":299`, 1),
		"session long":         strings.Replace(issuerBody(good), `"session_seconds":3600`, `"session_seconds":28801`, 1),
		"jwks missing":         `{"issuer":"` + dashIss + `","client_id":"c","authorize_url":"https://id.example.test/a"}`,
		"repeated member":      strings.Replace(issuerBody(good), `"client_id":"studio"`, `"client_id":"studio","client_id":"x"`, 1),
		"upper-case member":    strings.Replace(issuerBody(good), `"client_id":"studio"`, `"Client_id":"studio"`, 1),
	}
	is, _ = e.st.GetDashboardIssuer(context.Background())
	pushes := len(d.Calls())
	for name, body := range refused {
		t.Run(name, func(t *testing.T) {
			eb := e.wantCode(t, "PUT", "/v1/dashboard/issuer", body, 400, "bad_request")
			if strings.Contains(eb.Message, "\u001b") {
				t.Fatalf("%q", eb.Message)
			}
		})
	}
	after, _ := e.st.GetDashboardIssuer(context.Background())
	if !after.UpdatedAt.Equal(is.UpdatedAt) || len(d.Calls()) != pushes {
		t.Fatal("a refused set changed the issuer or pushed")
	}
	// Sixteen keys pass.
	strict(t, e.wantOK(t, "PUT", "/v1/dashboard/issuer", issuerBody(`{"keys":[`+strings.Join(sixteen, ",")+`]}`), 200), &doc)
	if len(doc.Kids) != 16 {
		t.Fatalf("%d kids", len(doc.Kids))
	}
}

func TestRevocations(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.setIssuer(t)
	type revT struct {
		Issuer     string `json:"issuer"`
		Subject    string `json:"subject"`
		NotBefore  string `json:"not_before"`
		Generation *int64 `json:"dashboard_generation"`
	}
	t0 := time.Now()
	var r revT
	strict(t, e.wantOK(t, "POST", "/v1/dashboard/revocations", `{"subject":"alice"}`, 200), &r)
	nb, err := time.Parse(time.RFC3339, r.NotBefore)
	if err != nil || r.Issuer != dashIss || r.Subject != "alice" || r.Generation == nil || nb.Before(t0.Truncate(time.Second)) ||
		nb.After(time.Now().Add(time.Second)) {
		t.Fatalf("%+v (%v)", r, err)
	}
	tbl, err := e.st.DashboardTable(context.Background())
	must(t, err)
	if len(tbl.Revoked) != 1 || tbl.Revoked[0].Subject != "alice" || tbl.Revoked[0].Issuer != dashIss {
		t.Fatalf("%+v", tbl.Revoked)
	}
	// The printed time is when the file starts refusing: never earlier than the stored one.
	if nb.Before(tbl.Revoked[0].NotBefore) {
		t.Fatalf("printed %v before stored %v", nb, tbl.Revoked[0].NotBefore)
	}
	strict(t, e.wantOK(t, "POST", "/v1/dashboard/revocations", `{"issuer":"https://x.example.test","subject":"a/b?c"}`, 200), &r)
	if r.Issuer != "https://x.example.test" || r.Subject != "a/b?c" {
		t.Fatalf("%+v", r)
	}
	if c := d.Calls(); len(c) != 3 || c[1] != "push" || c[2] != "push" {
		t.Fatalf("%q", c)
	}
	for _, b := range []string{`{}`, `{"subject":""}`, `{"subject":"a\u0000"}`, `{"subject":"a","extra":1}`, `{"subject":"a","Subject":"b"}`} {
		e.wantCode(t, "POST", "/v1/dashboard/revocations", b, 400, "bad_request")
	}
}

func TestDashboardShow_InForce(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	e.setIssuer(t)
	ctx := context.Background()
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "a", Role: "owner"}))
	must(t, e.st.AddMember(ctx, store.Member{Ref: demoRef, Issuer: dashIss, Subject: "b", Role: "developer"}))
	must(t, e.st.Revoke(ctx, dashIss, "x", time.Now()))
	var s dashShowJSON
	strict(t, e.wantOK(t, "GET", "/v1/dashboard", "", 200), &s)
	if s.StudioDomain != "studio.example.test" || s.InForce || s.Generation == nil || *s.Generation != 1 || s.Members != 2 || s.Revocations != 1 {
		t.Fatalf("%+v", s)
	}
	d.mu.Lock()
	d.inForce, d.gen = true, 42
	d.mu.Unlock()
	strict(t, e.wantOK(t, "GET", "/v1/dashboard", "", 200), &s)
	if !s.InForce || *s.Generation != 42 {
		t.Fatalf("%+v", s)
	}
	// Generation 0: no file at all.
	d.mu.Lock()
	d.inForce, d.gen = false, 0
	d.mu.Unlock()
	s = dashShowJSON{}
	strict(t, e.wantOK(t, "GET", "/v1/dashboard", "", 200), &s)
	if s.InForce || s.Generation != nil {
		t.Fatalf("%+v", s)
	}
	// It wrote nothing.
	if slices.Contains(d.Calls()[1:], "push") {
		t.Fatalf("%q", d.Calls())
	}
	// A failing read is an error, never in force.
	d.inForceErr = errors.New("store unavailable")
	e.wantCode(t, "GET", "/v1/dashboard", "", 500, "internal")
}

func TestProjectShow_Unchanged(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	before := e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200)
	keysBefore := e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/keys", "", 404)
	e.withDash(t, "dprj")
	e.setIssuer(t)
	e.member(t, "/members", `{"subject":"a","role":"owner"}`, 200)
	after := e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200)
	if string(before) != string(after) {
		t.Fatalf("project show changed:\n%s\n%s", before, after)
	}
	if k := e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/keys", "", 404); string(k) != string(keysBefore) {
		t.Fatalf("%s", k)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	return string(b)
}

// The refusal on a node without a studio domain points at init's help;
// dashboard show on a daemon that cannot write the file says so.
func TestMembers_Round2Texts(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	d.domain = ""
	eb := e.wantCode(t, "GET", "/v1/dashboard", "", 409, "conflict")
	if !strings.HasSuffix(eb.Message, "(see 'supapaced init --help')") {
		t.Fatalf("%q", eb.Message)
	}
	e.withDash(t, "drj")
	eb = e.wantCode(t, "GET", "/v1/dashboard", "", 409, "conflict")
	if eb.Message != "this daemon cannot write the dashboard file, so no member, issuer or revocation change is in force" {
		t.Fatalf("%q", eb.Message)
	}
}

// While containment is not verified, clean-jobs is refused before the
// project is looked up or any capability is called.
func TestMembers_CleanJobs_ContainmentFirst(t *testing.T) {
	e := newEnv(t)
	d := e.withDash(t, "dprj")
	e.active(t, demoRef)
	d.inForce, d.gen = true, 5
	e.ops.failed = true
	start := len(d.Calls())
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/members/clean-jobs", "", 503, "containment_failed")
	e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/members/clean-jobs", "", 503, "containment_failed")
	if len(d.Calls()) != start {
		t.Fatalf("%q", d.Calls()[start:])
	}
	e.ops.failed = false // control
	e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/members/clean-jobs", "", 200)
}
