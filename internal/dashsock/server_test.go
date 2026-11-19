package dashsock

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

const (
	refA    = "abcdefghij0123456789" // subnet 3, has its read-only secret
	refB    = "bcdefghij0123456789a" // subnet 4, no read-only secret
	refGone = "cdefghij0123456789ab" // not placed here: Facts answers ErrNotHere
	refDown = "defghij0123456789abc" // Facts answers a state that is not live
	iss     = "https://issuer.test"
	node    = "local"
	base    = "sp.test"

	// What the fake's secrets are; no log line may hold any of them.
	pwRW    = "rw-Pa$$:w/rd@1"
	pwRO    = "ro-Pa$$:w/rd@2"
	anonTok = "anon.TOKEN.value"
	svcTok  = "service.TOKEN.value"
)

var t0 = time.Date(2027, 1, 15, 8, 0, 0, 0, time.UTC)

// errNoRow is what the store's MemberRole returns without a row: an error the
// server cannot name, as the store's own sentinel is not importable here.
var errNoRow = errors.New("no member row")

// fakeStore implements Members and Projects. Facts answers only from facts;
// it never refuses a state itself, so a state check is the server's.
type fakeStore struct {
	mu        sync.Mutex
	facts     map[string]Facts
	members   map[[3]string]string // (ref, iss, sub) -> role
	ro        map[string]string
	pub       []jwtx.Key
	calls     []string
	slow      string // the method that blocks until its context ends
	deadline  time.Time
	calledAt  time.Time
	failWith  string // the method that fails, with an error text holding a secret
	nilPubKey bool
}

func (f *fakeStore) enter(ctx context.Context, m, ref string) error {
	f.mu.Lock()
	f.calls = append(f.calls, m+" "+ref)
	slow, fail := f.slow == m, f.failWith == m
	f.mu.Unlock()
	if slow {
		dl, _ := ctx.Deadline()
		f.mu.Lock()
		f.deadline, f.calledAt = dl, time.Now()
		f.mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	if fail {
		return errors.New("broken: " + pwRW + " " + svcTok)
	}
	return nil
}

func (f *fakeStore) MemberRole(ctx context.Context, ref, issuer, subject string) (string, error) {
	if err := f.enter(ctx, "MemberRole", ref); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.members[[3]string{ref, issuer, subject}]
	if !ok {
		return "", errNoRow
	}
	return r, nil
}

func (f *fakeStore) Facts(ctx context.Context, ref string) (Facts, error) {
	if err := f.enter(ctx, "Facts", ref); err != nil {
		return Facts{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fa, ok := f.facts[ref]
	if !ok {
		return Facts{}, ErrNotHere
	}
	return fa, nil
}

func (f *fakeStore) Passwords(ctx context.Context, ref string) (string, string, error) {
	if err := f.enter(ctx, "Passwords", ref); err != nil {
		return "", "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return pwRW, f.ro[ref], nil
}

func (f *fakeStore) Keys(ctx context.Context, ref string) (string, string, []jwtx.Key, error) {
	if err := f.enter(ctx, "Keys", ref); err != nil {
		return "", "", nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nilPubKey {
		return anonTok, svcTok, []jwtx.Key{{KID: "x", Class: "anon"}}, nil
	}
	return anonTok, svcTok, f.pub, nil
}

func (f *fakeStore) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

var (
	pubOnce sync.Once
	pubKeys []jwtx.Key
)

func testPub(t *testing.T) []jwtx.Key {
	pubOnce.Do(func() {
		for _, c := range []jwtx.Class{"anon", "service_role"} {
			priv, kid, err := jwtx.GenerateKey()
			if err != nil {
				panic(err)
			}
			pubKeys = append(pubKeys, jwtx.Key{KID: kid, Class: c, Pub: &priv.PublicKey})
		}
	})
	return pubKeys
}

func newFake(t *testing.T) *fakeStore {
	return &fakeStore{
		facts: map[string]Facts{
			refA:    {Name: "Shop", State: "active", Generation: 4, SubnetIndex: 3},
			refB:    {Name: "Blog", State: "restoring", Generation: 9, SubnetIndex: 4},
			refDown: {Name: "Old", State: "stopped", Generation: 2, SubnetIndex: 5},
		},
		members: map[[3]string]string{
			{refA, iss, "owner-1"}: dashcfg.RoleOwner, {refA, iss, "dev-1"}: dashcfg.RoleDeveloper,
			{refA, iss, "ro-1"}:    dashcfg.RoleReadOnly,
			{refB, iss, "owner-1"}: dashcfg.RoleOwner, {refB, iss, "dev-1"}: dashcfg.RoleDeveloper,
			{refB, iss, "ro-1"}:       dashcfg.RoleReadOnly,
			{refDown, iss, "owner-1"}: dashcfg.RoleOwner,
		},
		ro:  map[string]string{refA: pwRO},
		pub: testPub(t),
	}
}

// rig is one server on a real Unix socket with a frozen clock.
type rig struct {
	t     *testing.T
	s     *Server
	f     *fakeStore
	priv  ed25519.PrivateKey
	addrs dashcfg.Addrs
	sock  string
	cl    *http.Client
	clock struct {
		sync.Mutex
		now time.Time
	}
	peer atomic.Uint32
	logs *lockedBuf
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newRig(t *testing.T, tune ...func(*Server)) *rig {
	t.Helper()
	pubFile, privFile, err := genKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := dashcfg.For(nodecfg.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, f: newFake(t), priv: privFile, addrs: a, logs: &lockedBuf{}}
	r.peer.Store(dashcfg.StudioUID)
	r.clock.now = t0
	r.s = NewServer(pubFile, node, base, a, r.f, r.f)
	r.s.Log = slog.New(slog.NewJSONHandler(r.logs, nil))
	r.s.now = func() time.Time { r.clock.Lock(); defer r.clock.Unlock(); return r.clock.now }
	r.s.peerUID = func(net.Conn) (uint32, error) { return r.peer.Load(), nil }
	for _, f := range tune {
		f(r.s)
	}
	r.sock = filepath.Join(shortDir(t), "dash.sock")
	l, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.s.Serve(l) }()
	t.Cleanup(func() {
		l.Close()
		<-done
	})
	r.cl = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", r.sock)
		},
	}}
	t.Cleanup(r.cl.CloseIdleConnections)
	return r
}

func genKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	priv, pub, err := dashtok.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	k, err := dashtok.ParsePrivate(priv)
	if err != nil {
		return nil, nil, err
	}
	p, err := dashtok.ParsePublic(pub)
	return p, k, err
}

// setPeer changes the uid the next connection presents; the credentials are
// read once a connection, so idle ones are closed.
func (r *rig) setPeer(uid uint32) {
	r.peer.Store(uid)
	r.cl.CloseIdleConnections()
}

func (r *rig) advance(d time.Duration) {
	r.clock.Lock()
	r.clock.now = r.clock.now.Add(d)
	r.clock.Unlock()
}

func (r *rig) assertion(ref, sub, role, purpose string) string {
	r.t.Helper()
	r.clock.Lock()
	now := r.clock.now.Unix()
	r.clock.Unlock()
	tok, err := dashtok.SignAssertion(r.priv, dashtok.Assertion{Node: node, Iss: iss, Sub: sub, Name: "N",
		Ref: ref, Role: role, Purpose: purpose, Iat: now, Exp: now + 30})
	if err != nil {
		r.t.Fatal(err)
	}
	return tok
}

// call posts to path with the assertion and returns status, body.
func (r *rig) call(path, tok string) (int, []byte) {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "http://dash"+path, nil)
	req.Header.Set(HeaderAssertion, tok)
	resp, err := r.cl.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		r.t.Fatal(err)
	}
	return resp.StatusCode, b
}

func code(t *testing.T, b []byte) string {
	t.Helper()
	var c struct{ Code string }
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("refusal %q: %v", b, err)
	}
	return c.Code
}

func wantRefusal(t *testing.T, status int, body []byte, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || string(body) != `{"code":"`+wantCode+`"}` {
		t.Fatalf("got %d %q, want %d %s", status, body, wantStatus, wantCode)
	}
}

func TestServer_ChecksInOrder(t *testing.T) {
	r := newRig(t)
	_, foreignPriv, _ := genKey()
	foreign, _ := dashtok.SignAssertion(foreignPriv, dashtok.Assertion{Node: node, Iss: iss, Sub: "owner-1", Name: "N",
		Ref: refGone, Role: dashcfg.RoleOwner, Iat: t0.Unix(), Exp: t0.Unix() + 30})

	// 1: the peer — with every later check also failing (a foreign signature).
	r.setPeer(1000)
	st, b := r.call("/v1/resolve", foreign)
	wantRefusal(t, st, b, 403, "peer")
	if c := r.f.take(); len(c) != 0 {
		t.Fatalf("store read before the peer check: %v", c)
	}
	r.setPeer(dashcfg.StudioUID)

	// 2: the assertion — a foreign signature for a ref that is not here either.
	st, b = r.call("/v1/resolve", foreign)
	wantRefusal(t, st, b, 401, "bad_assertion")
	// An assertion for another node is refused the same way.
	wrongNode, _ := dashtok.SignAssertion(r.priv, dashtok.Assertion{Node: "other", Iss: iss, Sub: "owner-1", Name: "N",
		Ref: refA, Role: dashcfg.RoleOwner, Iat: t0.Unix(), Exp: t0.Unix() + 30})
	st, b = r.call("/v1/keys", wrongNode)
	wantRefusal(t, st, b, 401, "bad_assertion")
	st, b = r.call("/v1/keys", "")
	wantRefusal(t, st, b, 401, "bad_assertion")
	if c := r.f.take(); len(c) != 0 {
		t.Fatalf("store read before the assertion check: %v", c)
	}

	// 4: not here — and not a member either: only Facts ran.
	st, b = r.call("/v1/resolve", r.assertion(refGone, "nobody", dashcfg.RoleOwner, ""))
	wantRefusal(t, st, b, 404, "not_here")
	if c := r.f.take(); len(c) != 1 || c[0] != "Facts "+refGone {
		t.Fatalf("calls %v, want Facts alone", c)
	}

	// 5: not a member — Facts and MemberRole ran, nothing that holds a secret.
	st, b = r.call("/v1/keys", r.assertion(refA, "nobody", dashcfg.RoleOwner, "reveal"))
	wantRefusal(t, st, b, 403, "not_a_member")
	if c := r.f.take(); len(c) != 2 || c[0] != "Facts "+refA || c[1] != "MemberRole "+refA {
		t.Fatalf("calls %v, want Facts then MemberRole", c)
	}

	// Control: a member passes every check.
	if st, b = r.call("/v1/resolve", r.assertion(refA, "owner-1", dashcfg.RoleOwner, "")); st != 200 {
		t.Fatalf("control: %d %s", st, b)
	}
	r.f.take()

	// 3: the rate is counted before the store is read. A flood for a ref the
	// principal is not a member of: the burst is answered from the store, the
	// rest 429 with no read.
	tok := r.assertion(refB, "nobody", dashcfg.RoleOwner, "")
	var refused, limited int
	for range 100 {
		st, b := r.call("/v1/resolve", tok)
		switch code(t, b) {
		case "not_a_member":
			refused++
		case "rate_limited":
			if st != 429 {
				t.Fatalf("rate_limited with %d", st)
			}
			limited++
		default:
			t.Fatalf("unexpected %d %s", st, b)
		}
	}
	facts := 0
	for _, c := range r.f.take() {
		if strings.HasPrefix(c, "Facts ") {
			facts++
		}
	}
	if refused != 40 || limited != 60 || facts != 40 {
		t.Fatalf("refused %d, limited %d, store reads %d; want 40, 60, 40", refused, limited, facts)
	}
}

func TestServer_PeerOfAnotherUid_Refused(t *testing.T) {
	r := newRig(t)
	tok := r.assertion(refA, "owner-1", dashcfg.RoleOwner, "")
	for _, uid := range []uint32{0, 1000, dashcfg.PgMetaUID, dashcfg.PgcapUID} {
		r.setPeer(uid)
		st, b := r.call("/v1/resolve", tok)
		wantRefusal(t, st, b, 403, "peer")
	}
	if c := r.f.take(); len(c) != 0 {
		t.Fatalf("store read for a foreign peer: %v", c)
	}
	r.setPeer(dashcfg.StudioUID)
	if st, b := r.call("/v1/resolve", tok); st != 200 {
		t.Fatalf("control: %d %s", st, b)
	}

	// A peer whose credentials cannot be read is refused too.
	r2 := newRig(t, func(s *Server) {
		s.peerUID = func(net.Conn) (uint32, error) { return dashcfg.StudioUID, errors.New("no credentials") }
	})
	st, b := r2.call("/v1/resolve", r2.assertion(refA, "owner-1", dashcfg.RoleOwner, ""))
	wantRefusal(t, st, b, 403, "peer")

	// The credential reader is handed the socket itself, not a wrapper.
	r3 := newRig(t, func(s *Server) {
		s.peerUID = func(c net.Conn) (uint32, error) {
			if _, ok := c.(*net.UnixConn); !ok {
				return 0, errors.New("not the socket")
			}
			return dashcfg.StudioUID, nil
		}
	})
	if st, b := r3.call("/v1/resolve", r3.assertion(refA, "owner-1", dashcfg.RoleOwner, "")); st != 200 {
		t.Fatalf("the reader saw a wrapped connection: %d %s", st, b)
	}
}

// The default credential reader reads the real peer of a Unix socket.
func TestPeerUID_ReadsTheSocketsCredentials(t *testing.T) {
	sock := filepath.Join(shortDir(t), "p.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	uid, err := socketPeerUID(s)
	if err != nil || uid != uint32(os.Getuid()) {
		t.Fatalf("uid %d, %v; want %d", uid, err, os.Getuid())
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := socketPeerUID(a); err == nil {
		t.Fatal("a connection that is not a Unix socket has no peer uid")
	}
}

func resolve(t *testing.T, r *rig, ref, sub, role string) (ResolveAnswer, map[string]json.RawMessage) {
	t.Helper()
	st, b := r.call("/v1/resolve", r.assertion(ref, sub, role, ""))
	if st != 200 {
		t.Fatalf("%s %s: %d %s", ref, role, st, b)
	}
	var a ResolveAnswer
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return a, raw
}

func TestResolve_FieldsByRole(t *testing.T) {
	r := newRig(t)
	ver, err := nodecfg.LockedPostgresVersion()
	if err != nil || !regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`).MatchString(ver) {
		t.Fatalf("locked version %q, %v", ver, err)
	}
	for _, tc := range []struct {
		ref, sub, role string
		rw, ro         bool
		meta, subnet   int
	}{
		{refA, "owner-1", dashcfg.RoleOwner, true, true, 1, 3},
		{refA, "dev-1", dashcfg.RoleDeveloper, true, true, 1, 3},
		{refA, "ro-1", dashcfg.RoleReadOnly, false, true, 1, 3},
		{refB, "owner-1", dashcfg.RoleOwner, true, false, 0, 4},
		{refB, "dev-1", dashcfg.RoleDeveloper, true, false, 0, 4},
		{refB, "ro-1", dashcfg.RoleReadOnly, false, false, 0, 4},
	} {
		a, raw := resolve(t, r, tc.ref, tc.sub, tc.role)
		fa := r.f.facts[tc.ref]
		if a.Ref != tc.ref || a.Name != fa.Name || a.State != fa.State || a.Generation != fa.Generation ||
			a.DBVersion != ver || a.PgMeta != tc.meta || a.APIURL != "https://"+tc.ref+"."+base ||
			a.At != "2027-01-15T08:00:00Z" {
			t.Fatalf("%s %s: %+v", tc.ref, tc.role, a)
		}
		if strings.Join(a.DataAPI.Schemas, ",") != "public,graphql_public" ||
			strings.Join(a.DataAPI.ExtraSearchPath, ",") != "public,extensions" || string(raw["data_api"]) !=
			`{"schemas":["public","graphql_public"],"extra_search_path":["public","extensions"],"max_rows":null}` {
			t.Fatalf("data_api %s", raw["data_api"])
		}
		check := func(name string, want bool, login, pw string) {
			t.Helper()
			v, present := raw[name]
			if present != want {
				t.Fatalf("%s %s: %s present %v, want %v", tc.ref, tc.role, name, present, want)
			}
			if !want {
				return
			}
			var dsn string
			json.Unmarshal(v, &dsn)
			gotLogin, idx, err := dashcfg.ParseDSN(r.addrs, dsn)
			if err != nil || gotLogin != login || idx != tc.subnet {
				t.Fatalf("%s: login %q index %d err %v", name, gotLogin, idx, err)
			}
			u, _ := url.Parse(dsn)
			if p, _ := u.User.Password(); p != pw {
				t.Fatalf("%s carries another password", name)
			}
		}
		check("dsn_rw", tc.rw, dashcfg.LoginRW, pwRW)
		check("dsn_ro", tc.ro, dashcfg.LoginRO, pwRO)
		// Passwords are read only once the checks have passed, never Keys.
		for _, c := range r.f.take() {
			if strings.HasPrefix(c, "Keys") {
				t.Fatalf("resolve read the keys: %v", c)
			}
		}
	}
}

func TestResolve_NotHereOrNotLive(t *testing.T) {
	r := newRig(t)
	for _, ref := range []string{refGone, refDown} {
		for _, p := range []string{"/v1/resolve", "/v1/keys"} {
			st, b := r.call(p, r.assertion(ref, "owner-1", dashcfg.RoleOwner, "reveal"))
			wantRefusal(t, st, b, 404, "not_here")
		}
	}
	// Every live state is served; every other is not, whatever Facts says.
	for state, live := range map[string]bool{"active": true, "restarting": true, "restoring": true,
		"creating": false, "stopped": false, "deleting": false, "purged": false, "": false} {
		r.f.mu.Lock()
		fa := r.f.facts[refDown]
		fa.State = state
		r.f.facts[refDown] = fa
		r.f.mu.Unlock()
		st, b := r.call("/v1/resolve", r.assertion(refDown, "owner-1", dashcfg.RoleOwner, ""))
		if live && st != 200 || !live && (st != 404 || code(t, b) != "not_here") {
			t.Fatalf("state %q: %d %s", state, st, b)
		}
	}
}

func TestResolve_RemovedMemberRefused_WithAValidAssertion(t *testing.T) {
	r := newRig(t)
	tok := r.assertion(refA, "dev-1", dashcfg.RoleDeveloper, "")
	if st, b := r.call("/v1/resolve", tok); st != 200 {
		t.Fatalf("before removal: %d %s", st, b)
	}
	r.f.mu.Lock()
	delete(r.f.members, [3]string{refA, iss, "dev-1"})
	r.f.mu.Unlock()
	// The same assertion, still within its lifetime.
	for _, p := range []string{"/v1/resolve", "/v1/keys"} {
		st, b := r.call(p, tok)
		wantRefusal(t, st, b, 403, "not_a_member")
	}
	// Membership of another project does not carry over.
	st, b := r.call("/v1/resolve", r.assertion(refDown, "dev-1", dashcfg.RoleDeveloper, ""))
	wantRefusal(t, st, b, 404, "not_here")
	st, b = r.call("/v1/resolve", r.assertion(refB, "dev-1", dashcfg.RoleDeveloper, ""))
	if st != 200 {
		t.Fatalf("control: %d %s", st, b)
	}
}

func TestResolve_RoleMustMatchTheTable(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct{ sub, claimed string }{
		{"ro-1", dashcfg.RoleOwner}, {"ro-1", dashcfg.RoleDeveloper},
		{"dev-1", dashcfg.RoleOwner}, {"owner-1", dashcfg.RoleReadOnly},
	} {
		for _, p := range []string{"/v1/resolve", "/v1/keys"} {
			st, b := r.call(p, r.assertion(refA, tc.sub, tc.claimed, "reveal"))
			wantRefusal(t, st, b, 403, "not_a_member")
		}
	}
	// An issuer other than the stored one is another principal.
	tok, _ := dashtok.SignAssertion(r.priv, dashtok.Assertion{Node: node, Iss: "https://other.test", Sub: "owner-1",
		Name: "N", Ref: refA, Role: dashcfg.RoleOwner, Iat: t0.Unix(), Exp: t0.Unix() + 30})
	st, b := r.call("/v1/resolve", tok)
	wantRefusal(t, st, b, 403, "not_a_member")
	if c := r.f.take(); len(c) == 0 || strings.Contains(strings.Join(c, " "), "Passwords") ||
		strings.Contains(strings.Join(c, " "), "Keys") {
		t.Fatalf("calls %v", c)
	}
	if st, b := r.call("/v1/resolve", r.assertion(refA, "ro-1", dashcfg.RoleReadOnly, "")); st != 200 {
		t.Fatalf("control: %d %s", st, b)
	}
}

func TestKeys_ServiceKeyOnlyForOwnerWithReveal(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct{ sub, role string }{
		{"owner-1", dashcfg.RoleOwner}, {"dev-1", dashcfg.RoleDeveloper}, {"ro-1", dashcfg.RoleReadOnly},
	} {
		for _, purpose := range []string{"", "reveal"} {
			st, b := r.call("/v1/keys", r.assertion(refA, tc.sub, tc.role, purpose))
			if st != 200 {
				t.Fatalf("%s %q: %d %s", tc.role, purpose, st, b)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Fatal(err)
			}
			v, present := raw["service_role_key"]
			want := tc.role == dashcfg.RoleOwner && purpose == "reveal"
			if present != want || want && string(v) != `"`+svcTok+`"` {
				t.Fatalf("%s %q: service_role_key %s present %v", tc.role, purpose, v, present)
			}
			var k KeysAnswer
			json.Unmarshal(b, &k)
			if k.AnonKey != anonTok || len(k.SigningKeys) != 2 {
				t.Fatalf("%+v", k)
			}
			for i, sk := range k.SigningKeys {
				p := r.f.pub[i]
				if sk.Kid != p.KID || sk.Class != string(p.Class) || sk.Alg != "RS256" || sk.Kty != "RSA" ||
					sk.N != b64url(p.Pub.N.Bytes()) || sk.E != "AQAB" {
					t.Fatalf("signing key %d: %+v", i, sk)
				}
			}
		}
	}
	// A key without its public part is a fault: no answer.
	r.f.nilPubKey = true
	st, b := r.call("/v1/keys", r.assertion(refA, "owner-1", dashcfg.RoleOwner, "reveal"))
	wantRefusal(t, st, b, 503, "unavailable")
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestServer_StrictRequests(t *testing.T) {
	r := newRig(t)
	tok := r.assertion(refA, "owner-1", dashcfg.RoleOwner, "")
	raw := func(req string) (int, string) {
		t.Helper()
		c, err := net.Dial("unix", r.sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	hdr := "Host: dash\r\n" + HeaderAssertion + ": " + tok + "\r\n"
	for _, tc := range []struct {
		name, req string
		status    int
		code      string
	}{
		{"control", "POST /v1/resolve HTTP/1.1\r\n" + hdr + "Content-Length: 0\r\n\r\n", 200, ""},
		{"control without length", "POST /v1/keys HTTP/1.1\r\n" + hdr + "\r\n", 200, ""},
		{"body", "POST /v1/resolve HTTP/1.1\r\n" + hdr + "Content-Length: 2\r\n\r\n{}", 400, "bad_request"},
		{"chunked body", "POST /v1/resolve HTTP/1.1\r\n" + hdr + "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n", 400, "bad_request"},
		{"GET", "GET /v1/resolve HTTP/1.1\r\n" + hdr + "\r\n", 405, "method_not_allowed"},
		{"PUT", "PUT /v1/keys HTTP/1.1\r\n" + hdr + "Content-Length: 0\r\n\r\n", 405, "method_not_allowed"},
		{"another path", "POST /v1/token HTTP/1.1\r\n" + hdr + "\r\n", 404, "not_found"},
		{"trailing slash", "POST /v1/resolve/ HTTP/1.1\r\n" + hdr + "\r\n", 404, "not_found"},
		{"query", "POST /v1/resolve?x=1 HTTP/1.1\r\n" + hdr + "\r\n", 404, "not_found"},
		{"case", "POST /v1/Resolve HTTP/1.1\r\n" + hdr + "\r\n", 404, "not_found"},
		{"two assertions", "POST /v1/resolve HTTP/1.1\r\n" + hdr + HeaderAssertion + ": " + tok + "\r\n\r\n", 401, "bad_assertion"},
		{"header under the limit", "POST /v1/resolve HTTP/1.1\r\n" + hdr + "X-Pad: " + strings.Repeat("a", 6<<10) + "\r\n\r\n", 200, ""},
	} {
		st, b := raw(tc.req)
		if st != tc.status || tc.code != "" && b != `{"code":"`+tc.code+`"}` {
			t.Fatalf("%s: %d %q", tc.name, st, b)
		}
	}
	// The request header is bounded at 8 KiB, request line included.
	st, _ := raw("POST /v1/resolve HTTP/1.1\r\n" + hdr + "X-Pad: " + strings.Repeat("a", 8<<10) + "\r\n\r\n")
	if st != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("header over 8 KiB: %d", st)
	}
	r.f.take()
}

func TestServer_RatePerRef(t *testing.T) {
	r := newRig(t)
	a := r.assertion(refA, "owner-1", dashcfg.RoleOwner, "")
	b := r.assertion(refB, "owner-1", dashcfg.RoleOwner, "")
	burst := func(tok string, want int) {
		t.Helper()
		for i := range want {
			if st, body := r.call("/v1/resolve", tok); st != 200 {
				t.Fatalf("request %d: %d %s", i, st, body)
			}
		}
		st, body := r.call("/v1/keys", tok)
		wantRefusal(t, st, body, 429, "rate_limited")
	}
	burst(a, 40)
	// Another ref has its own bucket.
	burst(b, 40)
	// 20 a second: 49 ms is not one request, 50 ms is.
	r.advance(49 * time.Millisecond)
	burst(a, 0)
	r.advance(time.Millisecond)
	burst(a, 1)
	// A long pause refills to the burst, not beyond.
	r.advance(time.Hour)
	burst(r.assertion(refA, "owner-1", dashcfg.RoleOwner, ""), 40)
}

func TestServer_SlowStore_503Within800ms(t *testing.T) {
	for _, m := range []string{"Facts", "MemberRole", "Passwords", "Keys"} {
		t.Run(m, func(t *testing.T) {
			r := newRig(t)
			r.f.slow = m
			path := "/v1/resolve"
			if m == "Keys" {
				path = "/v1/keys"
			}
			tok := r.assertion(refA, "owner-1", dashcfg.RoleOwner, "")
			start := time.Now()
			st, b := r.call(path, tok)
			elapsed := time.Since(start)
			wantRefusal(t, st, b, 503, "unavailable")
			r.f.mu.Lock()
			dl, at := r.f.deadline, r.f.calledAt
			r.f.mu.Unlock()
			// The deadline was set when the request reached the handler, before
			// the store was called: at most 800 ms after that call.
			if dl.IsZero() || !dl.After(start) || dl.Sub(at) > 800*time.Millisecond {
				t.Fatalf("store context deadline %v after the store call", dl.Sub(at))
			}
			// Loose: only that the server does not wait for the store to return.
			if elapsed > 10*time.Second {
				t.Fatalf("answered after %v", elapsed)
			}
		})
	}
}

func TestServer_StoreFailure_503_NoSecretInLogOrAnswer(t *testing.T) {
	for _, m := range []string{"Facts", "Passwords", "Keys"} {
		r := newRig(t)
		r.f.failWith = m
		path := "/v1/resolve"
		if m == "Keys" {
			path = "/v1/keys"
		}
		st, b := r.call(path, r.assertion(refA, "owner-1", dashcfg.RoleOwner, "reveal"))
		wantRefusal(t, st, b, 503, "unavailable")
		logs := r.logs.String()
		if !strings.Contains(logs, refA) {
			t.Fatalf("%s: the failure is not logged: %s", m, logs)
		}
		for _, s := range secrets() {
			if strings.Contains(logs, s) {
				t.Fatalf("%s: log holds a secret", m)
			}
		}
	}
}

func secrets() []string {
	return []string{pwRW, pwRO, url.PathEscape(pwRW), url.PathEscape(pwRO), "rw-Pa", "ro-Pa", anonTok, svcTok,
		"TOKEN", "postgresql://"}
}

func TestServer_LogsResolutionsAndKeyReleases_NeverASecret(t *testing.T) {
	r := newRig(t)
	toks := []string{
		r.assertion(refA, "owner-1", dashcfg.RoleOwner, "reveal"),
		r.assertion(refA, "ro-1", dashcfg.RoleReadOnly, ""),
		r.assertion(refA, "dev-1", dashcfg.RoleDeveloper, "reveal"),
	}
	var answers string
	for _, tok := range toks {
		for _, p := range []string{"/v1/resolve", "/v1/keys"} {
			st, b := r.call(p, tok)
			if st != 200 {
				t.Fatalf("%d %s", st, b)
			}
			answers += string(b)
		}
	}
	r.call("/v1/resolve", r.assertion(refA, "nobody", dashcfg.RoleOwner, ""))
	// Control: the answers did carry the secrets.
	for _, s := range []string{anonTok, svcTok, "postgresql://"} {
		if !strings.Contains(answers, s) {
			t.Fatalf("control: answers lack a secret")
		}
	}
	logs := r.logs.String()
	for _, s := range append(secrets(), toks...) {
		if strings.Contains(logs, s) {
			t.Fatalf("log holds a secret or an assertion:\n%s", logs)
		}
	}
	var resolves, releases []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		switch m["msg"] {
		case "dashboard resolve":
			resolves = append(resolves, m)
		case "dashboard service key released":
			releases = append(releases, m)
		}
	}
	if len(resolves) != 3 || len(releases) != 1 {
		t.Fatalf("%d resolve lines, %d release lines:\n%s", len(resolves), len(releases), logs)
	}
	for i, want := range []string{"owner-1", "ro-1", "dev-1"} {
		m := resolves[i]
		if m["ref"] != refA || m["sub"] != want || m["iss"] != iss || m["role"] == "" {
			t.Fatalf("resolve line %v", m)
		}
	}
	if m := releases[0]; m["ref"] != refA || m["sub"] != "owner-1" || m["iss"] != iss {
		t.Fatalf("release line %v", m)
	}
}

func TestServer_ConnectionCap(t *testing.T) {
	r := newRig(t, func(s *Server) { s.maxConns = 2 })
	tok := r.assertion(refA, "owner-1", dashcfg.RoleOwner, "")
	var held []net.Conn
	for range 2 {
		c, err := net.Dial("unix", r.sock)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	// Both held connections are served (so both were accepted).
	for _, c := range held {
		fmt.Fprintf(c, "POST /v1/resolve HTTP/1.1\r\nHost: dash\r\n%s: %s\r\n\r\n", HeaderAssertion, tok)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("held connection: %v %v", resp, err)
		}
		resp.Body.Close()
	}
	// A third is not served while both are open...
	third, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	fmt.Fprintf(third, "POST /v1/resolve HTTP/1.1\r\nHost: dash\r\n%s: %s\r\n\r\n", HeaderAssertion, tok)
	got := make(chan int, 1)
	go func() {
		resp, err := http.ReadResponse(bufio.NewReader(third), nil)
		if err != nil {
			got <- -1
			return
		}
		resp.Body.Close()
		got <- resp.StatusCode
	}()
	select {
	case st := <-got:
		t.Fatalf("a connection over the cap was served: %d", st)
	case <-time.After(200 * time.Millisecond):
	}
	// ...and is served once one closes.
	held[0].Close()
	select {
	case st := <-got:
		if st != 200 {
			t.Fatalf("after a close: %d", st)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the third connection was never served")
	}
	held[1].Close()
}

func TestListen_DirectoryAndSocketModes_StaleSocketReplaced(t *testing.T) {
	root := shortDir(t)
	p := dashcfg.PathsFor(nodecfg.Paths{Root: root})
	type ch struct {
		path     string
		uid, gid int
	}
	var chowns []ch
	old := chown
	chown = func(path string, uid, gid int) error { chowns = append(chowns, ch{path, uid, gid}); return nil }
	t.Cleanup(func() { chown = old })

	check := func() net.Listener {
		t.Helper()
		chowns = nil
		l, err := Listen(p)
		if err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(p.SocketDir(), "dash.sock")
		for path, want := range map[string]os.FileMode{p.SocketDir(): os.ModeDir | 0o750, sock: os.ModeSocket | 0o660} {
			fi, err := os.Lstat(path)
			if err != nil || fi.Mode() != want {
				t.Fatalf("%s: mode %v, want %v (%v)", path, fi.Mode(), want, err)
			}
		}
		if len(chowns) != 2 || chowns[0] != (ch{p.SocketDir(), 0, dashcfg.StudioUID}) ||
			chowns[1] != (ch{sock, 0, dashcfg.StudioUID}) {
			t.Fatalf("chowns %v", chowns)
		}
		// It accepts.
		go func() {
			c, err := net.Dial("unix", sock)
			if err == nil {
				c.Close()
			}
		}()
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		return l
	}
	check().Close()

	// A directory with a wider mode is narrowed; a stale socket left behind
	// (its listener gone without unlinking it) is replaced.
	if err := os.Chmod(p.SocketDir(), 0o777); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(p.SocketDir(), "dash.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("stale socket not left behind: %v", err)
	}
	check().Close()

	// Anything at the socket's path that is not a socket — a symlink (to a
	// file or to a socket), a regular file, a directory — is an error and is
	// left as it was. The stale socket above is the control.
	target := filepath.Join(root, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other.sock")
	ol, err := net.ListenUnix("unix", &net.UnixAddr{Name: other, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ol.Close()
	for _, plant := range []struct {
		name string
		make func() error
		mode os.FileMode
	}{
		{"symlink to a file", func() error { return os.Symlink(target, sock) }, os.ModeSymlink},
		{"symlink to a socket", func() error { return os.Symlink(other, sock) }, os.ModeSymlink},
		{"regular file", func() error { return os.WriteFile(sock, []byte("keep"), 0o600) }, 0},
		{"directory", func() error { return os.Mkdir(sock, 0o700) }, os.ModeDir},
	} {
		if err := os.Remove(sock); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := plant.make(); err != nil {
			t.Fatal(err)
		}
		if l, err := Listen(p); err == nil {
			l.Close()
			t.Fatalf("%s at the socket path: accepted", plant.name)
		}
		if fi, err := os.Lstat(sock); err != nil || fi.Mode().Type() != plant.mode {
			t.Fatalf("%s: not left alone (%v, %v)", plant.name, fi, err)
		}
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "x" {
		t.Fatalf("symlink target touched: %q %v", b, err)
	}
	if fi, err := os.Lstat(other); err != nil || fi.Mode().Type() != os.ModeSocket {
		t.Fatalf("the other socket was touched: %v %v", fi, err)
	}
	os.Remove(sock)

	// A socket directory that is not a directory is refused.
	os.RemoveAll(p.SocketDir())
	if err := os.Symlink(root, p.SocketDir()); err != nil {
		t.Fatal(err)
	}
	if l, err := Listen(p); err == nil {
		l.Close()
		t.Fatal("a symlinked socket directory was accepted")
	}
}

// shortDir is a temporary directory with a short path: a Unix socket's path is
// limited to 107 bytes, which a test's own temporary directory can pass.
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "ds")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// A server handed addresses without a proxy (Static's zero for a node For
// refuses) renders no connection string: a resolve that would carry one is
// unavailable.
func TestResolve_ZeroProxyAddress_NoConnectionString(t *testing.T) {
	r := newRig(t, func(s *Server) { s.addrs = dashcfg.Addrs{} })
	st, b := r.call("/v1/resolve", r.assertion(refA, "owner-1", dashcfg.RoleOwner, ""))
	wantRefusal(t, st, b, 503, "unavailable")
	// A member who is given no connection string is not affected either.
	st, b = r.call("/v1/resolve", r.assertion(refB, "ro-1", dashcfg.RoleReadOnly, ""))
	if st != 200 {
		t.Fatalf("no string to render: %d %s", st, b)
	}
	if st, b := r.call("/v1/keys", r.assertion(refA, "owner-1", dashcfg.RoleOwner, "")); st != 200 {
		t.Fatalf("control: %d %s", st, b)
	}
}

// served reports whether a new connection gets a 200 for a valid request
// within wait.
func (r *rig) served(wait time.Duration) bool {
	r.t.Helper()
	c, err := net.Dial("unix", r.sock)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST /v1/resolve HTTP/1.1\r\nHost: dash\r\n%s: %s\r\n\r\n", HeaderAssertion,
		r.assertion(refA, "owner-1", dashcfg.RoleOwner, ""))
	c.SetReadDeadline(time.Now().Add(wait))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// A connection that never finishes its request, or never reads its answers,
// gives its slot back within the request's bounds.
func TestServer_StalledConnection_FreesItsSlot(t *testing.T) {
	for _, tc := range []struct {
		name string
		peer uint32
		send func(c net.Conn)
	}{
		{"declared body never sent", dashcfg.StudioUID, func(c net.Conn) {
			io.WriteString(c, "POST /v1/resolve HTTP/1.1\r\nHost: dash\r\nContent-Length: 10\r\n\r\n")
		}},
		{"chunked body never sent, foreign peer", 1000, func(c net.Conn) {
			io.WriteString(c, "POST /v1/resolve HTTP/1.1\r\nHost: dash\r\nTransfer-Encoding: chunked\r\n\r\n")
		}},
		{"answers never read", dashcfg.StudioUID, func(c net.Conn) {
			req := strings.Repeat("POST /x HTTP/1.1\r\nHost: d\r\n\r\n", 1000)
			go func() {
				for range 200 {
					if _, err := io.WriteString(c, req); err != nil {
						return
					}
				}
			}()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(s *Server) { s.maxConns = 1 })
			r.peer.Store(tc.peer)
			c, err := net.Dial("unix", r.sock)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			tc.send(c)
			time.Sleep(200 * time.Millisecond) // the stalled connection holds the slot
			r.peer.Store(dashcfg.StudioUID)
			if !r.served(15 * time.Second) {
				t.Fatal("the slot of a stalled connection was never given back")
			}
		})
	}
}

// The request line and header together may be 8 KiB, not a byte more.
func TestServer_HeaderLimitIsExact(t *testing.T) {
	r := newRig(t)
	pre := "POST /v1/resolve HTTP/1.1\r\nHost: dash\r\n" + HeaderAssertion + ": " +
		r.assertion(refA, "owner-1", dashcfg.RoleOwner, "") + "\r\nX-Pad: "
	for total, want := range map[int]int{8 << 10: 200, 8<<10 + 1: 431} {
		c, err := net.Dial("unix", r.sock)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, pre+strings.Repeat("a", total-len(pre)-4)+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if err != nil || resp.StatusCode != want {
			t.Fatalf("%d bytes: %v %v, want %d", total, resp, err, want)
		}
	}
}

// A handler that panics gives its connection's slot back.
func TestServer_HandlerPanic_FreesItsSlot(t *testing.T) {
	var p atomic.Bool
	p.Store(true)
	r := newRig(t, func(s *Server) {
		s.maxConns = 1
		s.projects = switchable{s.projects.(*fakeStore), &p}
	})
	r.cl.Transport.(*http.Transport).DisableKeepAlives = true
	req, _ := http.NewRequest(http.MethodPost, "http://dash/v1/resolve", nil)
	req.Header.Set(HeaderAssertion, r.assertion(refA, "owner-1", dashcfg.RoleOwner, ""))
	if resp, err := r.cl.Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("a panicking handler answered %d", resp.StatusCode)
	}
	p.Store(false)
	if !r.served(15 * time.Second) {
		t.Fatal("the slot of a panicked connection was never given back")
	}
}

type switchable struct {
	*fakeStore
	panics *atomic.Bool
}

func (s switchable) Facts(ctx context.Context, ref string) (Facts, error) {
	if s.panics.Load() {
		panic("store fault")
	}
	return s.fakeStore.Facts(ctx, ref)
}
