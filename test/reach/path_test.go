//go:build reach

package reach

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
)

const (
	whoamiPath  = "/rest/v1/rpc/whoami"
	headersPath = "/rest/v1/rpc/headers"
)

// hdr builds a header from name, value pairs; repeated names add values.
func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func bearer(tok string) string { return "Bearer " + tok }

// wantRole requires a 200 whose whoami() body is the JSON string role.
func wantRole(t testing.TB, what string, resp *http.Response, role string) {
	t.Helper()
	var got string
	if resp.StatusCode != 200 || json.Unmarshal(bodyOf(resp), &got) != nil || got != role {
		t.Fatalf("%s: want 200 with whoami() = %q, got %s (whoami %q)", what, role, describe(resp), got)
	}
}

// signed is a token over claims (exp five minutes ahead unless set) signed by
// priv with kid.
func signed(t testing.TB, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	c := map[string]any{"iat": time.Now().Unix(), "exp": time.Now().Unix() + 300}
	for k, v := range claims {
		c[k] = v
	}
	tok, err := jwtx.Sign(priv, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// headersOf returns the request headers PostgREST saw, from headers().
func headersOf(t testing.TB, what string, resp *http.Response) map[string]string {
	t.Helper()
	var h map[string]string
	if resp.StatusCode != 200 || json.Unmarshal(bodyOf(resp), &h) != nil {
		t.Fatalf("%s: want 200 with headers(), got %s", what, describe(resp))
	}
	return h
}

// TestReach01_Signature: A's anon, service and user tokens are refused on B's
// host and by B's PostgREST; each refusal follows the same token accepted by A.
func TestReach01_Signature(t *testing.T) {
	A, B := fixtureAB(t)
	wantRole(t, "control: B's own anon key on B's host", gatewayDo(t, B, "GET", whoamiPath, hdr("apikey", B.AnonKey), nil), "anon")
	user := A.UserToken("authenticated", nil)
	for _, c := range []struct {
		name, role, token string
		onA, onB          http.Header
		code              string // the gateway's refusal on B's host
	}{
		{"anon key", "anon", A.AnonKey, hdr("apikey", A.AnonKey), hdr("apikey", A.AnonKey), "invalid_apikey"},
		{"service key", "service_role", A.ServiceKey, hdr("apikey", A.ServiceKey), hdr("apikey", A.ServiceKey), "invalid_apikey"},
		// B's own anon key as apikey, so only the bearer is A's.
		{"user token", "authenticated", user, hdr("apikey", A.AnonKey, "Authorization", bearer(user)),
			hdr("apikey", B.AnonKey, "Authorization", bearer(user)), "invalid_token"},
	} {
		t.Run(strings.ReplaceAll(c.name, " ", "_"), func(t *testing.T) {
			wantRole(t, "twin: A's "+c.name+" on A's host", gatewayDo(t, A, "GET", whoamiPath, c.onA, nil), c.role)
			wantGatewayRefusal(t, "A's "+c.name+" on B's host", gatewayDo(t, B, "GET", whoamiPath, c.onB, nil), 401, c.code)

			if reached, status := postgrestDirect(t, A, c.token); !reached || status != 200 {
				t.Fatalf("twin: A's %s at A's PostgREST directly: reached %v, status %d, want 200", c.name, reached, status)
			}
			if reached, status := postgrestDirect(t, B, c.token); !reached || status != 401 {
				t.Fatalf("A's %s at B's PostgREST directly: reached %v, status %d, want 401", c.name, reached, status)
			}
		})
	}
	// The gateway bypassed: a token signed HS256 with the text of A's public key
	// set (as PostgREST is given it) as the secret is refused by A's PostgREST,
	// after an RS256 token of A's issuer is accepted there.
	t.Run("hs256_with_key_set_direct", func(t *testing.T) {
		if reached, status := postgrestDirect(t, A, A.UserToken("authenticated", nil)); !reached || status != 200 {
			t.Fatalf("twin: an RS256 token of A's issuer at A's PostgREST: reached %v, status %d, want 200", reached, status)
		}
		jwks := renderedJWKS(t, A)
		payload := fmt.Sprintf(`{"role":"authenticated","sub":%q,"exp":%d}`, newUUID(), time.Now().Unix()+300)
		for _, secret := range [][]byte{jwks, bytes.TrimSpace(jwks)} {
			for _, header := range []string{`{"alg":"HS256","typ":"JWT"}`, fmt.Sprintf(`{"alg":"HS256","typ":"JWT","kid":%q}`, A.IssuerKID)} {
				if reached, status := postgrestDirect(t, A, hs256Token(header, payload, secret)); !reached || status != 401 {
					t.Fatalf("HS256 keyed with the key set (%d bytes, header %s): reached %v, status %d, want 401", len(secret), header, reached, status)
				}
			}
		}
	})
}

// TestReach02_KeyRole walks the key→role table: eight refusals, each after its
// accepted twin, and four acceptances.
func TestReach02_KeyRole(t *testing.T) {
	A, B := fixtureAB(t)
	kAnon, kidAnon := platformKey(t, A, "jwt.anon.private")
	kSvc, kidSvc := platformKey(t, A, "jwt.service_role.private")
	fresh, freshKID, err := jwtx.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	user := A.UserToken("authenticated", nil)
	// Tokens of A's platform keys: each with its own role (accepted, which shows
	// the key read from the store is the one the gateway holds) and with a role
	// its class may not carry.
	ownAnon := signed(t, kAnon, kidAnon, map[string]any{"role": "anon"})
	ownSvc := signed(t, kSvc, kidSvc, map[string]any{"role": "service_role"})
	forgedAnon := signed(t, kAnon, kidAnon, map[string]any{"role": "service_role"})
	forgedSvc := signed(t, kSvc, kidSvc, map[string]any{"role": "authenticated"})
	now := time.Now().Unix()
	q := func(key string) string { return whoamiPath + "?apikey=" + url.QueryEscape(key) }

	type req struct {
		path string
		h    http.Header
	}
	bearerReq := func(tok string) req { return req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(tok))} }
	type row struct {
		name     string
		twin     req
		twinRole string
		bad      req
		code     string
	}
	// Bearers PostgREST alone would serve; only the gateway refuses them. The
	// same cases are checked by TestHelpers_GatewayOnlyBearers.
	twinSpec, cases := gatewayOnlyBearers(A.IssuerKID, newUUID(), now+300)
	var extra []row
	for _, c := range cases {
		extra = append(extra, row{c.name, bearerReq(twinSpec.sign(t, A.Issuer)), "authenticated",
			bearerReq(c.bad.sign(t, A.Issuer)), "invalid_token"})
	}
	for _, r := range append([]row{
		{"R1_issuer_claims_service_role",
			req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(A.UserToken("authenticated", nil)))}, "authenticated",
			req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(A.UserToken("service_role", nil)))}, "invalid_token"},
		{"R2_anon_key_claims_service_role",
			req{whoamiPath, hdr("apikey", ownAnon, "Authorization", bearer(ownAnon))}, "anon",
			req{whoamiPath, hdr("apikey", forgedAnon, "Authorization", bearer(forgedAnon))}, "invalid_apikey"},
		{"R3_service_key_claims_authenticated",
			req{whoamiPath, hdr("apikey", ownSvc, "Authorization", bearer(ownSvc))}, "service_role",
			req{whoamiPath, hdr("apikey", forgedSvc, "Authorization", bearer(forgedSvc))}, "invalid_apikey"},
		{"R4_expired",
			req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(A.UserToken("authenticated", map[string]any{"exp": now + 300})))}, "authenticated",
			req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(A.UserToken("authenticated", map[string]any{"exp": now - 1})))}, "invalid_token"},
		{"R5_unknown_kid",
			req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(user))}, "authenticated",
			req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(signed(t, fresh, freshKID, map[string]any{"role": "authenticated", "sub": newUUID()})))}, "invalid_token"},
		{"R6_no_apikey",
			req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(user))}, "authenticated",
			req{whoamiPath, hdr("Authorization", bearer(user))}, "no_apikey"},
		{"R7_header_and_query_differ",
			req{q(A.AnonKey), hdr("apikey", A.AnonKey)}, "anon",
			req{q(A.ServiceKey), hdr("apikey", A.AnonKey)}, "invalid_apikey"},
		{"R8_foreign_apikey",
			req{whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(user))}, "authenticated",
			req{whoamiPath, hdr("apikey", B.AnonKey, "Authorization", bearer(user))}, "invalid_apikey"},
	}, extra...) {
		t.Run(r.name, func(t *testing.T) {
			wantRole(t, "twin", gatewayDo(t, A, "GET", r.twin.path, r.twin.h, nil), r.twinRole)
			wantGatewayRefusal(t, "refusal", gatewayDo(t, A, "GET", r.bad.path, r.bad.h, nil), 401, r.code)
		})
	}
	for _, a := range []struct {
		name, path string
		h          http.Header
		role       string
	}{
		{"A1_anon_key", whoamiPath, hdr("apikey", A.AnonKey), "anon"},
		{"A2_service_key", whoamiPath, hdr("apikey", A.ServiceKey), "service_role"},
		{"A3_user_token", whoamiPath, hdr("apikey", A.AnonKey, "Authorization", bearer(user)), "authenticated"},
		{"A4_query_apikey", q(A.AnonKey), nil, "anon"},
	} {
		t.Run(a.name, func(t *testing.T) {
			wantRole(t, a.name, gatewayDo(t, A, "GET", a.path, a.h, nil), a.role)
		})
	}
}

// waitREST polls a GET through the gateway until it returns 200 (PostgREST's
// schema cache reloads asynchronously after DDL).
func waitREST(t testing.TB, p Project, path string, h http.Header) *http.Response {
	t.Helper()
	var resp *http.Response
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if resp = gatewayDo(t, p, "GET", path, h, nil); resp.StatusCode == 200 {
			return resp
		}
	}
	t.Fatalf("GET %s on %s: no 200 within 30 s, last %s", path, p.Ref, describe(resp))
	return nil
}

// TestReach08_AuthUID: under RLS using (auth.uid() = owner) each user sees
// exactly their own row; the table holds both rows.
func TestReach08_AuthUID(t *testing.T) {
	A, _ := fixtureAB(t)
	u1, u2 := newUUID(), newUUID()
	t.Cleanup(func() {
		if _, err := sqlAs(t, A, "postgres", "drop table if exists public.reach_t8; notify pgrst, 'reload schema';"); err != nil {
			t.Errorf("dropping reach_t8: %v", err)
		}
	})
	if _, err := sqlAs(t, A, "postgres", fmt.Sprintf(`drop table if exists public.reach_t8;
create table public.reach_t8 (owner uuid primary key);
alter table public.reach_t8 enable row level security;
create policy own on public.reach_t8 for select to authenticated using (auth.uid() = owner);
grant select on public.reach_t8 to authenticated;
insert into public.reach_t8 values ('%s'), ('%s');
notify pgrst, 'reload schema';`, u1, u2)); err != nil {
		t.Fatal(err)
	}
	if n, err := sqlAs(t, A, "postgres", "select count(*) from public.reach_t8"); err != nil || n != "2" {
		t.Fatalf("control: the table holds %q rows (%v), want 2", n, err)
	}
	for _, u := range []string{u1, u2} {
		h := hdr("apikey", A.AnonKey, "Authorization", bearer(A.UserToken("authenticated", map[string]any{"sub": u})))
		resp := waitREST(t, A, "/rest/v1/reach_t8?select=owner", h)
		var rows []struct{ Owner string }
		if json.Unmarshal(bodyOf(resp), &rows) != nil || len(rows) != 1 || rows[0].Owner != u {
			t.Fatalf("user %s sees %s, want exactly their own row", u, redact(string(bodyOf(resp))))
		}
	}
}

// TestReach12_GatewayHeaders: client-sent forwarding and connection headers are
// replaced or removed; exactly one Authorization reaches PostgREST, and a
// request with two is refused.
func TestReach12_GatewayHeaders(t *testing.T) {
	A, _ := fixtureAB(t)
	user := A.UserToken("authenticated", nil)
	h := hdr("apikey", A.AnonKey, "Authorization", bearer(user),
		"X-Forwarded-Host", "evil.test", "X-Forwarded-For", "203.0.113.9", "X-Forwarded-Proto", "http",
		"Forwarded", "for=203.0.113.9", "X-Real-IP", "203.0.113.9", "True-Client-IP", "203.0.113.9",
		"x-pg-application-name", "evil", "x-connection-encrypted", "true", "x-reach-marker", "kept")
	got := headersOf(t, "headers()", gatewayDo(t, A, "GET", headersPath, h, nil))
	if got["x-reach-marker"] != "kept" {
		t.Fatal("control: an ordinary client header did not reach headers()")
	}
	src := nodeAddr(t).String() // a connection to the node's own address leaves from it
	for name, want := range map[string]string{
		"x-forwarded-host":      A.Ref + "." + nodeConf(t).Domain,
		"x-forwarded-proto":     "https",
		"x-forwarded-for":       src,
		"x-pg-application-name": "supapace-gateway",
	} {
		if got[name] != want {
			t.Errorf("%s upstream = %q, want %q", name, got[name], want)
		}
	}
	for _, name := range []string{"x-connection-encrypted", "forwarded", "x-real-ip", "true-client-ip", "apikey"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s reached PostgREST", name)
		}
	}
	if got["authorization"] != bearer(user) {
		t.Error("the Authorization upstream is not the client's bearer")
	}

	one := hdr("apikey", A.AnonKey, "Authorization", bearer(user))
	if headersOf(t, "twin: one Authorization", gatewayDo(t, A, "GET", headersPath, one, nil))["authorization"] != bearer(user) {
		t.Fatal("twin: one Authorization header: not forwarded as sent")
	}
	two := hdr("apikey", A.AnonKey, "Authorization", bearer(user), "Authorization", bearer(user))
	wantGatewayRefusal(t, "two Authorization headers", gatewayDo(t, A, "GET", headersPath, two, nil), 401, "invalid_token")
}

// TestReach15_GraphQL: A's GraphQL route answers under the caller's role: a
// table granted to authenticated only is visible to a user and, while anon sees
// its own table on the same path, not to anon. B, without pg_graphql, fails
// cleanly with a 4xx from PostgREST.
func TestReach15_GraphQL(t *testing.T) {
	A, B := fixtureAB(t)
	const drop = "drop table if exists public.reach_t15, public.reach_t15_pub;"
	t.Cleanup(func() {
		if _, err := sqlAs(t, A, "postgres", drop); err != nil {
			t.Errorf("dropping reach_t15: %v", err)
		}
	})
	if _, err := sqlAs(t, A, "postgres", drop+`
create table public.reach_t15 (id int primary key);
insert into public.reach_t15 values (1);
revoke all on public.reach_t15 from anon;
grant select on public.reach_t15 to authenticated;
create table public.reach_t15_pub (id int primary key);
insert into public.reach_t15_pub values (2);
grant select on public.reach_t15_pub to anon;`); err != nil {
		t.Fatal(err)
	}
	type edges struct {
		Edges []struct{ Node struct{ ID int } }
	}
	type gql struct {
		Data struct {
			Restricted *edges `json:"reach_t15Collection"`
			Public     *edges `json:"reach_t15_pubCollection"`
		}
		Errors []json.RawMessage
	}
	post := func(what string, h http.Header, coll string) gql {
		h.Set("Content-Type", "application/json")
		resp := gatewayDo(t, A, "POST", "/graphql/v1", h, []byte(`{"query":"{ `+coll+` { edges { node { id } } } }"}`))
		var g gql
		if resp.StatusCode != 200 || json.Unmarshal(bodyOf(resp), &g) != nil {
			t.Fatalf("%s: want 200 with a GraphQL document, got %s", what, describe(resp))
		}
		return g
	}
	one := func(e *edges, id int) bool { return e != nil && len(e.Edges) == 1 && e.Edges[0].Node.ID == id }
	user := hdr("apikey", A.AnonKey, "Authorization", bearer(A.UserToken("authenticated", nil)))
	if g := post("A as authenticated", user, "reach_t15Collection"); !one(g.Data.Restricted, 1) || len(g.Errors) != 0 {
		t.Fatal("A as authenticated: the authenticated-only table did not answer its one row")
	}
	if g := post("control: A as anon, anon's table", hdr("apikey", A.AnonKey), "reach_t15_pubCollection"); !one(g.Data.Public, 2) || len(g.Errors) != 0 {
		t.Fatal("control: A as anon: the anon-visible table did not answer its one row")
	}
	if g := post("A as anon", hdr("apikey", A.AnonKey), "reach_t15Collection"); g.Data.Restricted != nil || len(g.Errors) == 0 {
		t.Fatal("A as anon: the authenticated-only table was visible, or no GraphQL error was returned")
	}

	query := []byte(`{"query":"{ reach_t15Collection { edges { node { id } } } }"}`)
	wantRole(t, "control: B serves REST", gatewayDo(t, B, "GET", whoamiPath, hdr("apikey", B.AnonKey), nil), "anon")
	resp := gatewayDo(t, B, "POST", "/graphql/v1", hdr("apikey", B.AnonKey, "Content-Type", "application/json"), query)
	var e struct {
		Code string `json:"code"`
	}
	json.Unmarshal(bodyOf(resp), &e)
	if resp.StatusCode < 400 || resp.StatusCode > 499 || resp.StatusCode == 401 || !strings.HasPrefix(e.Code, "PGRST") {
		t.Fatalf("B without pg_graphql: want a 4xx from PostgREST (code PGRST…), got %s", describe(resp))
	}
}

// jsonPad is a valid JSON body of n bytes: {} and spaces.
func jsonPad(n int) []byte { return append([]byte("{}"), bytes.Repeat([]byte(" "), n-2)...) }

// TestReach17_GatewayLimits: slow body, body cap, per-source connection cap and
// header cap, each refusal paired with its accepted control.
func TestReach17_GatewayLimits(t *testing.T) {
	A, _ := fixtureAB(t)
	src1 := nodeAddr(t)
	anon := hdr("apikey", A.AnonKey, "Content-Type", "application/json")

	t.Run("a_slow_body", func(t *testing.T) {
		body := jsonPad(1 << 20)
		resp, err := connDo(t, gatewayConn(t, A, src1), "POST", whoamiPath, anon, body)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("control: the body sent at once: %s", outcome(resp, err))
		}

		head := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s.%s\r\napikey: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n",
			whoamiPath, A.Ref, nodeConf(t).Domain, A.AnonKey, len(body))
		type end struct {
			status int
			after  time.Duration
		}
		ended := make(chan end, 1)
		// The request line is written as soon as the handshake ends, and the
		// window is measured from that write.
		c := gatewayConn(t, A, src1)
		c.SetReadDeadline(time.Now().Add(80 * time.Second))
		start := time.Now()
		if _, err := io.WriteString(c, head); err != nil {
			t.Fatal(err)
		}
		go func() {
			br := bufio.NewReader(c)
			status := 0
			if resp, err := http.ReadResponse(br, nil); err == nil {
				status = resp.StatusCode
				io.Copy(io.Discard, br) // until the close
			}
			ended <- end{status, time.Since(start)}
		}()
		var e end
	feed:
		for i := 0; ; i++ {
			select {
			case e = <-ended:
				break feed
			case <-time.After(time.Second):
				if time.Since(start) > 75*time.Second {
					t.Fatal("a body sent one byte per second was not cut within 75 s")
				}
				c.Write(body[i : i+1]) // fails once the gateway has closed; the reader reports when
			}
		}
		if e.status != 0 && e.status != 400 {
			t.Fatalf("slow body: answered %d, want the connection closed (a 400 at most)", e.status)
		}
		if e.after < 60*time.Second || e.after > 70*time.Second {
			t.Fatalf("slow body: connection closed %v after the request line, want 60–70 s", e.after.Round(time.Millisecond))
		}
	})

	t.Run("b_body_cap", func(t *testing.T) {
		if resp := gatewayDo(t, A, "POST", whoamiPath, anon, jsonPad(1<<20)); resp.StatusCode == 413 {
			t.Fatalf("control: a 1 MiB body was refused: %s", describe(resp))
		}
		wantGatewayRefusal(t, "8 MiB + 1 byte", gatewayDo(t, A, "POST", whoamiPath, anon, jsonPad(8<<20+1)), 413, "body_too_large")
	})

	t.Run("c_per_source_cap", func(t *testing.T) {
		src2 := addSourceAddr(t)
		xff := map[netip.Addr]string{}
		for _, src := range []netip.Addr{src1, src2} {
			c := gatewayConn(t, A, src)
			resp, err := connDo(t, c, "GET", headersPath, anon, nil)
			c.Close() // not counted against the cap below
			if err != nil {
				t.Fatalf("control: request from %v: %s", src, errText(err))
			}
			xff[src] = headersOf(t, "control: headers() from "+src.String(), resp)["x-forwarded-for"]
		}
		time.Sleep(time.Second) // the gateway counts closed connections out as it reads their EOF
		if xff[src1] != src1.String() || xff[src2] != src2.String() {
			t.Fatalf("control: X-Forwarded-For per source %q, want each source's own address", xff)
		}

		var held []io.Closer
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		hold := func(n int) { // n keep-alive connections from src1, each after one completed request
			for range n {
				c := gatewayConn(t, A, src1)
				held = append(held, c)
				if resp, err := connDo(t, c, "GET", whoamiPath, anon, nil); err != nil || resp.StatusCode != 200 {
					t.Fatalf("connection %d from %v: %s", len(held), src1, outcome(resp, err))
				}
			}
		}
		hold(63)
		hold(1) // the 64th: below the cap, served
		if c, err := dialGateway(t, A, src1); err == nil {
			_, err = connDo(t, c, "GET", whoamiPath, anon, nil)
			c.Close()
			if err == nil {
				t.Fatal("the 65th connection from one source was served")
			}
		}
		resp, err := connDo(t, gatewayConn(t, A, src2), "GET", whoamiPath, anon, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("control: a second source while the first is at its cap: %s", outcome(resp, err))
		}
	})

	t.Run("d_header_cap", func(t *testing.T) {
		// The connections of c are closed; give the gateway a moment to count them out.
		var resp *http.Response
		var err error
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			h := hdr("apikey", A.AnonKey, "x-reach-pad", strings.Repeat("a", 16<<10))
			if resp, err = gatewayRoundTrip(t, A, "GET", headersPath, h, nil, src1); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("control: 16 KiB header: %s", errText(err))
		}
		if len(headersOf(t, "control: 16 KiB header", resp)["x-reach-pad"]) != 16<<10 {
			t.Fatal("control: the 16 KiB header did not arrive whole")
		}
		h := hdr("apikey", A.AnonKey, "x-reach-pad", strings.Repeat("a", 40<<10))
		resp, err = gatewayRoundTrip(t, A, "GET", headersPath, h, nil, src1)
		if err == nil && resp.StatusCode != 431 {
			t.Fatalf("40 KiB header: want 431 or the connection closed, got %s", describe(resp))
		}
	})
}
