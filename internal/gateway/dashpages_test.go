package gateway

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashtok"
)

// TestAuthAnswers_GatewayPagesPolicy_ScriptHashMatches_NoStore sends one
// request for every page, refusal and redirect of the sign-in handler, on the
// sign-in host and on a dashboard host, and checks on each: the dashboard's
// headers with the transport-security header, no-store, and the policy of the
// gateway's pages — the hash of the one script the body holds ('none' when it
// holds none), the hash of its style, and form-action 'none' on every answer
// but the relay page, whose form-action is exactly the origin it posts to.
// Origin-Agent-Cluster is on every answer of the sign-in host and on none of
// a dashboard host.
func TestAuthAnswers_GatewayPagesPolicy_ScriptHashMatches_NoStore(t *testing.T) {
	e := newAuthEnv(t)
	now := time.Now().Unix()
	mark := func(host string) string {
		return "https://" + host + "/-/auth/session?at=" + strconv.FormatInt(now-5, 10)
	}
	tk := e.ticket(t, dashtok.Ticket{Iss: issuer, Sub: subOwnerA, Refs: []string{refA, refB}, Iat: now, Exp: now + 60})
	type answer struct {
		name   string
		r      func() *http.Request
		status int
		script string // the page's script, "" for none
		action string // the form-action, "" for 'none'
	}
	var answers []answer
	add := func(name string, status int, script, action string, r func() *http.Request) {
		answers = append(answers, answer{name, r, status, script, action})
	}
	for _, h := range []struct{ host, ref string }{{signInH, "_"}, {dhostA, refA}} {
		host, ref := h.host, h.ref
		login := func(q string) attemptT { return e.login(t, host, q) }
		add("login redirect", 302, "", "", func() *http.Request { return get(host, "/-/auth/login") })
		add("login redirect, sixteen cleared", 302, "", "", func() *http.Request {
			var cs []string
			for i := range 16 {
				cs = append(cs, "__Host-sp-login-x"+strconv.Itoa(1000000000+i)+"=v")
			}
			return get(host, "/-/auth/login", "Cookie", strings.Join(cs, "; "))
		})
		add("session page", 200, nextScript, "", func() *http.Request {
			at := login("")
			return post(host, "/-/auth/session", form(idToken(t, issuerSigner, idClaims(subOwnerA, at.nonce)), at.state), "Cookie", at.cookie)
		})
		add("retry page", 200, nextScript, "", func() *http.Request {
			return post(host, "/-/auth/session", form("x", login("").state))
		})
		add("final page, the cookie's words", 401, "", "", func() *http.Request {
			return post(host, "/-/auth/session", form("x", login("?retry=1").state))
		})
		add("final page, the other words", 401, "", "", func() *http.Request {
			at := login("?retry=1")
			return post(host, "/-/auth/session", form(idToken(t, issuerSigner, idClaims(subOwnerA, "x")), at.state), "Cookie", at.cookie)
		})
		add("token refused", 401, "", "", func() *http.Request {
			at := login("")
			return post(host, "/-/auth/session", form("x", at.state), "Cookie", at.cookie)
		})
		add("session refused, 400", 400, "", "", func() *http.Request { return post(host, "/-/auth/session", "") })
		add("session, another method", 405, "", "", func() *http.Request { return get(host, "/-/auth/session") })
		add("log-out without a session", 302, "", "", func() *http.Request { return get(host, "/-/auth/logout") })
		add("log-out with a session", 302, "", "", func() *http.Request {
			return get(host, "/-/auth/logout", "Cookie", e.sessionOf(t, ref, subOwnerA))
		})
		add("ticket refused", 400, "", "", func() *http.Request { return get(host, "/-/auth/logout?t=x") })
		add("unknown path", 404, "", "", func() *http.Request { return get(host, "/-/auth/x") })
		add("cross-origin", 403, "", "", func() *http.Request {
			return get(host, "/-/auth/login", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "cors")
		})
		add("not presented", 401, "", "", func() *http.Request {
			return get(host, "/", append(navTo("same-origin"), "Referer", mark(host))...)
		})
	}
	add("relay page to a project", 200, relayScript, "https://"+dhostA, func() *http.Request {
		return post(signInH, "/-/auth/callback", form("x", "v1."+refA+".AAAAAAAAAAA.0.Lw"))
	})
	add("relay page to another project", 200, relayScript, "https://"+dhostB, func() *http.Request {
		return post(signInH, "/-/auth/callback", form("x", "v1."+refB+".AAAAAAAAAAA.0.Lw"))
	})
	add("relay page to the sign-in host", 200, relayScript, signInO, func() *http.Request {
		return post(signInH, "/-/auth/callback", form("x", "v1._.AAAAAAAAAAA.0.Lw"))
	})
	add("callback refused", 400, "", "", func() *http.Request { return post(signInH, "/-/auth/callback", "") })
	add("callback, another method", 405, "", "", func() *http.Request { return get(signInH, "/-/auth/callback") })
	add("callback on a dashboard host", 404, "", "", func() *http.Request { return post(dhostA, "/-/auth/callback", "") })
	add("signed-out page", 200, "", "", func() *http.Request { return get(signInH, "/-/auth/signed-out") })
	add("signed-out page, both sentences", 200, "", "", func() *http.Request { return get(signInH, "/-/auth/signed-out?more=1&ended=0") })
	add("picker", 200, "", "", func() *http.Request { return get(signInH, "/", "Cookie", e.sessionOf(t, "_", subOwnerA)) })
	add("picker, navigation without a session", 302, "", "", func() *http.Request { return get(signInH, "/", navTo("none")...) })
	add("picker, a fetch without a session", 401, "", "", func() *http.Request { return get(signInH, "/") })
	add("sign-in host, unknown path", 404, "", "", func() *http.Request { return get(signInH, "/x") })
	add("a hop", 302, "", "", func() *http.Request { return get(dhostA, "/-/auth/logout?t="+tk) })

	statuses := map[int]bool{}
	for _, a := range answers {
		r := a.r()
		host := r.Host
		name := a.name + " on " + host
		action := a.action
		if action == "" {
			action = "'none'"
		}
		w := e.do(r)
		if w.Code != a.status {
			t.Errorf("%s: %d %s, want %d", name, w.Code, w.Body, a.status)
			continue
		}
		statuses[w.Code] = true
		if s := policyWrong(host, w, action); s != "" {
			t.Errorf("%s: %s", name, s)
		}
		// Stated here once more, independently of the helper: the policy as
		// one string, with the hash of the script the page is to hold.
		script := "'none'"
		if a.script != "" {
			script = hashOf(a.script)
			if got := scriptRE.FindStringSubmatch(w.Body.String()); got == nil || got[1] != a.script {
				t.Errorf("%s: the page's script is %q", name, got)
			}
		} else if strings.Contains(w.Body.String(), "<script") {
			t.Errorf("%s: a script on a page that has none", name)
		}
		want := "default-src 'none'; script-src " + script + "; style-src " + hashOf(pageStyle) +
			"; frame-ancestors 'none'; base-uri 'none'; form-action " + action
		if got := w.Header().Values("Content-Security-Policy"); len(got) != 1 || got[0] != want {
			t.Errorf("%s: policy %q\nwant %q", name, got, want)
		}
		if a.action == "" && !strings.HasSuffix(w.Header().Get("Content-Security-Policy"), "; form-action 'none'") {
			t.Errorf("%s: form-action is not 'none'", name)
		}
		if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
			t.Errorf("%s: Strict-Transport-Security %q", name, got)
		}
		if oac := w.Header().Values("Origin-Agent-Cluster"); (host == signInH) != (len(oac) == 1 && oac[0] == "?1") || host != signInH && len(oac) != 0 {
			t.Errorf("%s: Origin-Agent-Cluster %q", name, oac)
		}
		if isPage(w) {
			if got := styleRE.FindStringSubmatch(w.Body.String()); got == nil || got[1] != pageStyle {
				t.Errorf("%s: the page's style is %q", name, got)
			}
		}
	}
	for _, s := range []int{200, 302, 400, 401, 403, 404, 405} {
		if !statuses[s] {
			t.Errorf("no answer of status %d was checked", s)
		}
	}
	// The three constants are what the hashes are of, and each is in use.
	if relayScript == "" || nextScript == "" || pageStyle == "" || relayScript == nextScript {
		t.Error("the pages' script and style constants")
	}
	// The relay's form-action is never the studio domain itself: no state
	// names it as a target.
	if w := e.ask(t, post(signInH, "/-/auth/callback", form("x", "v1."+studioDom+".AAAAAAAAAAA.0.Lw"))); w.Code != 400 {
		t.Errorf("a state that names the studio domain: %d", w.Code)
	}
}
