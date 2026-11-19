package gateway

import (
	"os"
	"testing"
)

// TestSignInHost_EveryAnswerAsksForItsOwnAgentCluster: also the answers made
// before the sign-in handler is reached — a path the path rule refuses, and
// no table — and none of a dashboard host or of the studio domain.
func TestSignInHost_EveryAnswerAsksForItsOwnAgentCluster(t *testing.T) {
	e := newAuthEnv(t)
	check := func(name, host, target string, status int, want bool) {
		t.Helper()
		w := e.do(rawReq("GET", host, target))
		oac := w.Header().Values("Origin-Agent-Cluster")
		if w.Code != status || want != (len(oac) == 1 && oac[0] == "?1") || !want && len(oac) != 0 {
			t.Errorf("%s: %d, Origin-Agent-Cluster %q", name, w.Code, oac)
		}
	}
	check("the path rule, sign-in host", signInH, "/a/../b", 400, true)
	check("the handler, sign-in host", signInH, "/x", 404, true)
	check("the path rule, a dashboard host", dhostA, "/a/../b", 400, false)
	check("the studio domain", studioDom, "/", 302, false)
	if err := os.Remove(e.path()); err != nil {
		t.Fatal(err)
	}
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	check("no table, sign-in host", signInH, "/", 503, true)
	check("no table, a dashboard host", dhostA, "/", 503, false)
}
