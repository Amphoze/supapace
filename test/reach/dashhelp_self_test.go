//go:build !reach

package reach

// Self-tests of the dashboard helpers that need no node.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
)

func TestDashHelp_IDTokenVerifiesUnderVerifyID(t *testing.T) {
	priv, kid, set, err := dashNewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwtx.ParseDashboardJWKS(set)
	if err != nil || len(keys) != 1 || keys[0].KID != kid {
		t.Fatalf("the key set %s: %v %v", set, keys, err)
	}
	now := time.Now()
	tok, err := dashIDToken(priv, kid, "https://issuer.test", "user-1", "n-1", now)
	if err != nil {
		t.Fatal(err)
	}
	want := jwtx.IDCheck{Issuer: "https://issuer.test", ClientID: dashClientID, Nonce: "n-1"}
	c, err := jwtx.VerifyID(tok, keys, want, now)
	if err != nil || c.Sub != "user-1" || c.Exp-c.Iat != 300 {
		t.Fatalf("VerifyID: %+v %v", c, err)
	}
	// Controls: another nonce, issuer or key is refused.
	if _, err := jwtx.VerifyID(tok, keys, jwtx.IDCheck{Issuer: want.Issuer, ClientID: dashClientID, Nonce: "n-2"}, now); !errors.Is(err, jwtx.ErrNonce) {
		t.Errorf("another nonce: %v", err)
	}
	if _, err := jwtx.VerifyID(tok, keys, jwtx.IDCheck{Issuer: "https://other.test", ClientID: dashClientID, Nonce: "n-1"}, now); !errors.Is(err, jwtx.ErrClaim) {
		t.Errorf("another issuer: %v", err)
	}
	_, _, other, _ := dashNewIssuer()
	okeys, _ := jwtx.ParseDashboardJWKS(other)
	if _, err := jwtx.VerifyID(tok, okeys, want, now); err == nil {
		t.Error("another issuer's key set accepted the token")
	}
	// The key set is of the dashboard's class only: the project path refuses it.
	if _, err := jwtx.VerifyID(tok, []jwtx.Key{{KID: kid, Class: "issuer", Pub: &priv.PublicKey}}, want, now); !errors.Is(err, jwtx.ErrKey) {
		t.Errorf("a key of the project issuer's class: %v", err)
	}
}

func TestDashHelp_AssertionWithAChosenKey(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	a := dashtok.Assertion{Node: "local", Iss: "https://issuer.test", Sub: "user-1", Ref: "abcdefghij0123456789", Role: "owner"}
	tok, err := dashAssert(key, a, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := dashtok.VerifyAssertion(pub, tok, "local", now)
	if err != nil || got.Exp-got.Iat != 30 || got.Iat != now.Unix() || got.Sub != "user-1" {
		t.Fatalf("VerifyAssertion: %+v %v", got, err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := dashtok.VerifyAssertion(other, tok, "local", now); !errors.Is(err, dashtok.ErrSignature) {
		t.Errorf("another key: %v", err)
	}
}

func TestDashHelp_ScenarioJSON(t *testing.T) {
	off := false
	for _, c := range []struct {
		s    dashScenario
		want string
	}{
		{dashScenario{Engine: "chromium", Hosts: map[string]string{"studio.test": "127.0.0.1"}, CA: "/ca/ca.pem", Timeout: 45000,
			Steps: []map[string]any{{"goto": "https://studio.test/"}, {"eval": "window.isSecureContext"}}},
			`{"engine":"chromium","hosts":{"studio.test":"127.0.0.1"},"ca":"/ca/ca.pem","timeout_ms":45000,"steps":[{"goto":"https://studio.test/"},{"eval":"window.isSecureContext"}]}`},
		{dashScenario{Engine: "webkit", Hosts: map[string]string{}, Script: &off, Steps: []map[string]any{{"drive": "https://x.test/"}}},
			`{"engine":"webkit","hosts":{},"timeout_ms":0,"script":false,"steps":[{"drive":"https://x.test/"}]}`},
	} {
		b, err := json.Marshal(c.s)
		if err != nil || string(b) != c.want {
			t.Errorf("got %s %v\nwant %s", b, err, c.want)
		}
	}
}

func TestDashHelp_ClientSendsFetchMetadata(t *testing.T) {
	seen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Clone() }))
	defer srv.Close()
	c := &http.Client{Transport: dashFetch{base: http.DefaultTransport, origin: "https://a.studio.test",
		cookies: []*http.Cookie{{Name: "__Host-sp-session", Value: "v1.x"}}}}
	send := func(method string, h ...string) http.Header {
		t.Helper()
		r, _ := http.NewRequest(method, srv.URL+"/x", nil)
		for i := 0; i+1 < len(h); i += 2 {
			r.Header.Set(h[i], h[i+1])
		}
		resp, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return <-seen
	}
	pick := func(h http.Header) map[string]string {
		m := map[string]string{}
		for _, n := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Origin", "Cookie"} {
			if v, ok := h[n]; ok {
				m[n] = strings.Join(v, ",")
			}
		}
		return m
	}
	cookie := "__Host-sp-session=v1.x"
	for _, c := range []struct {
		name   string
		method string
		h      []string
		want   map[string]string
	}{
		{"fetch", "GET", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Cookie": cookie}},
		{"post", "POST", nil, map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
			"Origin": "https://a.studio.test", "Cookie": cookie}},
		{"navigation", "GET", []string{"Accept", "text/html,application/xhtml+xml"}, map[string]string{"Sec-Fetch-Site": "same-origin",
			"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1", "Cookie": cookie}},
		{"the test's own value is kept", "POST", []string{"Sec-Fetch-Site", "cross-site", "Origin", "https://evil.test"},
			map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
				"Origin": "https://evil.test", "Cookie": cookie}},
	} {
		if got := pick(send(c.method, c.h...)); !maps.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDashHelp_PathForms(t *testing.T) {
	const a, b = "abcdefghij0123456789", "bcdefghij0123456789a"
	got := dashPathForms("/project/"+a+"/sql", a, b)
	want := map[string]string{
		"plain":             "/project/" + a + "/sql",
		"dotdot":            "/x/../project/" + a + "/sql",
		"dotdot_encoded":    "/x/%2e%2e/project/" + a + "/sql",
		"dot_mixed":         "/x/.%2E/project/" + a + "/sql",
		"double_encoding":   "/x/%252e%252e/project/" + a + "/sql",
		"overlong_dot":      "/x/%C0%AE/project/" + a + "/sql",
		"upper":             "/PROJECT/" + a + "/sql",
		"control":           "/project/" + a + "/sql%01",
		"double_slash":      "/project//" + a + "/sql",
		"backslash":         `/project\` + a + "/sql",
		"backslash_encoded": "/project%5c" + a + "/sql",
		"encoded_slash":     "/project%2f" + a + "/sql",
		"fragment_end":      "/project/" + a + "/sql#",
		"fragment_dotdot":   "/project/" + a + "/sql#/../x",
		"fragment_0":        "/project#/" + a + "/sql",
		"fragment_1":        "/project/" + a + "#/sql",
		"foreign_1":         "/project/" + b + "/sql",
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		if got[k] != want[k] {
			t.Errorf("%s: %q, want %q", k, got[k], want[k])
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d forms, want %d", len(got), len(want))
	}
	// A static segment with a k gets the Kelvin sign; a one-segment path has
	// no slash to double.
	k := dashPathForms("/api/keys", "", "")
	if k["kelvin"] != "/api/%E2%84%AAeys" || k["encoded_slash"] != "/api%2fkeys" {
		t.Errorf("kelvin %q, encoded slash %q", k["kelvin"], k["encoded_slash"])
	}
	if one := dashPathForms("/api", "", ""); one["double_slash"] != "" || one["fragment_end"] != "/api#" {
		t.Errorf("one segment: %v", one)
	}
}
