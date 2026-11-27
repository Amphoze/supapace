package saga

import (
	"context"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

// TestRestart_R6_RefusedVerifierStoresNoSecret: when the cluster refuses the
// read-only login's verifier, the restart fails at R6 after the project
// serves again, and no secret is stored — the secret's existence is the
// record that the cluster has the verifier. A retry once the refusal is gone
// sets the login and stores the secret.
func TestRestart_R6_RefusedVerifierStoresNoSecret(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.dropReadOnlySecret(ref)
	e.ag.setErr(failOn("SetReadOnlyLogin"))
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	op := e.waitState(id, "failed")
	if op.Step != "S6" && op.Step != "R5" || strings.Contains(op.LastError, "stays restarting") {
		t.Fatalf("op %+v", op)
	}
	if e.hasReadOnlySecret(ref) {
		t.Fatal("a secret was stored although the verifier was refused")
	}
	if p := e.project(ref); p.State != "active" || p.AppliedGen != 2 {
		t.Fatalf("project %+v", p)
	}
	if got := e.ag.readOnlyLogins(); len(got) != 0 {
		t.Fatalf("%d logins took effect", len(got))
	}
	e.ag.setErr(nil)
	must(t, e.st.RetryOperation(context.Background(), id))
	e.waitState(id, "done")
	if got := e.ag.readOnlyLogins(); len(got) != 1 || got[0] != e.secret(ref, dashcfg.SecretROPassword) {
		t.Fatalf("after the retry: %d logins set", len(got))
	}
}
