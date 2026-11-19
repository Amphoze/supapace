package gateway

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/routes"
)

// Many goroutines on one bucket at one instant are granted exactly the burst:
// no lost update mints a token.
func TestRate_ConcurrentTakesNeverExceedBurst(t *testing.T) {
	var l rates
	r := &routes.Rate{RPS: 10, Burst: 50}
	now := time.Unix(1000, 0)
	var granted atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if l.allow("x", r, now) {
					granted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if g := granted.Load(); g != 50 {
		t.Fatalf("granted %d, want the burst of 50", g)
	}
}

// A very long pause refills to the burst and no further, at either end of
// the bounds.
func TestRate_HugeElapsedRefillsToTheBurstOnly(t *testing.T) {
	for _, r := range []*routes.Rate{{RPS: 1, Burst: 1}, {RPS: 100000, Burst: 1000000}} {
		var l rates
		t0 := time.Unix(0, 0)
		for l.allow("x", r, t0) {
		}
		later := t0.Add(200 * 365 * 24 * time.Hour)
		n := 0
		for l.allow("x", r, later) {
			n++
		}
		if n != r.Burst {
			t.Errorf("rate %d/%d: after a long pause served %d", r.RPS, r.Burst, n)
		}
	}
}

// A refused request gets the fixed body and dials nothing.
func TestRate_RefusalDialsNothing(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, withRate(&routes.Rate{RPS: 1, Burst: 1}, refA))
	frozen(e, refA, 1, 1, 1)
	anon := a.anon.token(t, "anon")
	e.expect(t, "first", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
	e.reset()
	w := e.do(withKey(req("GET", hostA, "/rest/v1/", nil), anon))
	if w.Code != 429 || strings.TrimSpace(w.Body.String()) != `{"code":"too_many_requests"}` || len(e.dialed) != 0 {
		t.Fatalf("%d %s, dialled %v", w.Code, w.Body, e.dialed)
	}
}

// A reload of the table neither refills nor resets a bucket, nor does
// removing the project and adding it back.
func TestRate_ReloadNeitherRefillsNorResets(t *testing.T) {
	a, _, _ := keys()
	rate := &routes.Rate{RPS: 1, Burst: 1}
	e := newEnv(t, withRate(rate, refA))
	frozen(e, refA, 1, 1, 1)
	anon := a.anon.token(t, "anon")
	e.expect(t, "first", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
	reload := func(f *routes.File, gen int64) {
		f.Generation = gen
		writeFile(t, e.path, *f)
		if err := e.gw.table.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	reload(withRate(rate, refA), 2)
	e.expect(t, "after a reload", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 429, "too_many_requests")
	gone := withRate(rate, refA)
	delete(gone.Projects, refA)
	reload(gone, 3)
	e.expect(t, "removed", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 404, "not_found")
	reload(withRate(rate, refA), 4)
	e.expect(t, "added back", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 429, "too_many_requests")
}

// The stopped answer comes before the upgrade refusal, and a stopped project
// takes no token.
func TestStopped_BeforeTheUpgradeRefusal(t *testing.T) {
	a, _, _ := keys()
	f := stoppedA()
	p := f.Projects[refA]
	p.Rate = &routes.Rate{RPS: 1, Burst: 1}
	f.Projects[refA] = p
	e := newEnv(t, f)
	r := withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon"))
	r.Header.Set("Upgrade", "websocket")
	e.expect(t, "upgrade", r, 503, "project_stopped")
	if len(e.gw.rates.m) != 0 {
		t.Fatalf("a stopped project took a token: %v", e.gw.rates.m)
	}
}

// The audience is read as JSON: escapes decode, the member name is exact,
// duplicates and a long list are fine.
func TestAud_JSONFormsOfTheMember(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, withAud([]string{"app"}))
	anon := a.anon.token(t, "anon")
	long := make([]string, 1000)
	for i := range long {
		long[i] = "x"
	}
	for _, c := range []struct {
		name   string
		tok    string
		status int
	}{
		{"escaped", rawIssuerToken(t, a.iss, `"aud":"app"`), 200},
		{"upper-case name", rawIssuerToken(t, a.iss, `"AUD":"app"`), 401},
		{"duplicates", audToken(t, a.iss, []string{"app", "app"}), 200},
		{"listed last of a thousand", audToken(t, a.iss, append(long, "app")), 200},
		{"a thousand unlisted", audToken(t, a.iss, long), 401},
	} {
		r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
		r.Header.Set("Authorization", "Bearer "+c.tok)
		code := ""
		if c.status == 401 {
			code = "invalid_token"
		}
		e.expect(t, c.name, r, c.status, code)
	}
}

// rawIssuerToken signs a payload with the extra member written verbatim.
func rawIssuerToken(t *testing.T, s signer, member string) string {
	t.Helper()
	tok, err := jwtx.Sign(s.priv, s.kid, map[string]any{"role": "authenticated", "exp": time.Now().Unix() + 300})
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign with the member spliced into the payload's JSON.
	parts := strings.Split(tok, ".")
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	pb = append(pb[:len(pb)-1], []byte(","+member+"}")...)
	return resign(t, s, parts[0], base64.RawURLEncoding.EncodeToString(pb))
}

// An asleep entry is not proxied while the gateway has no wake: it gets the
// answer a node without the wake socket gives (red until the gateway refuses
// the state).
func TestAsleep_NotServedWithoutAWake(t *testing.T) {
	a, _, _ := keys()
	f := file(1, "asleep")
	e := newEnv(t, &f)
	e.reset()
	w := e.do(withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon")))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "project_restarting") || len(e.dialed) != 0 {
		t.Fatalf("asleep: %d %s, dialled %v", w.Code, w.Body, e.dialed)
	}
}

func resign(t *testing.T, s signer, header, payload string) string {
	t.Helper()
	h := sha256.Sum256([]byte(header + "." + payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// The bucket is the project's, whatever form of its host the client sends.
func TestRate_KeyedOnTheProjectNotTheHostForm(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, withRate(&routes.Rate{RPS: 1, Burst: 1}, refA))
	frozen(e, refA, 1, 1, 1)
	anon := a.anon.token(t, "anon")
	e.expect(t, "plain host", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
	e.expect(t, "host with a port", withKey(req("GET", hostA+":443", "/rest/v1/", nil), anon), 429, "too_many_requests")
}

// A request that passed the key check takes a token even when its path is
// unknown or its declared body too large: the bucket counts what a key
// holder makes the gateway do.
func TestRate_AuthenticatedRefusalsAfterTheKeyCheckTakeATokenEach(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, withRate(&routes.Rate{RPS: 1, Burst: 2}, refA))
	frozen(e, refA, 2, 1, 2)
	anon := a.anon.token(t, "anon")
	e.expect(t, "unknown path", withKey(req("GET", hostA, "/nope", nil), anon), 404, "not_found")
	big := withKey(req("POST", hostA, "/rest/v1/t", nil), anon)
	big.ContentLength = maxBody + 1
	e.expect(t, "declared body too large", big, 413, "body_too_large")
	e.expect(t, "then a valid one", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 429, "too_many_requests")
}
