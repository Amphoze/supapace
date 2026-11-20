package main

import (
	"os"
	"strings"
	"testing"
)

// A removal or a revocation whose dashboard file is not in force says that
// the principal is still admitted. RED until the wording of the review.
func TestReview_CLI_CutOffNotInForce_SaysStillAdmitted(t *testing.T) {
	for _, c := range []struct {
		body string
		args []string
	}{
		{`{"code":"not_in_force","message":"committed; not yet in force: dashboard file: disk full",` +
			memberDoc("", "developer", "unchanged", `,"rotation":null,"still_valid":null,"jobs":null`)[1:],
			[]string{"member", "remove", mref, "--subject", "alice"}},
		{`{"code":"not_in_force","message":"committed; not yet in force: dashboard file: disk full","issuer":"i","subject":"s",` +
			`"not_before":"2026-11-19T10:00:00Z","dashboard_generation":null}` + "\n", []string{"dashboard", "revoke", "i", "s"}},
	} {
		f := newFake(t, reply{503, c.body})
		out, stderr, code := f.run(t, c.args...)
		if code != 1 || out != c.body || !strings.Contains(stderr, "still admitted") {
			t.Fatalf("%q: %d %q", c.args, code, stderr)
		}
	}
}

// A rotation whose gateway or REST step failed says that the old key may
// still pass. RED until the wording of the review.
func TestReview_CLI_RotationNotInForce_SaysOldKeyMayPass(t *testing.T) {
	body := `{"code":"not_in_force","message":"committed; not yet in force: service-key rotation: gateway: timeout","ref":"` + mref +
		`","service_key":"rotated","rotation":{"gateway":"failed: timeout","rest":"skipped: no running service"}}` + "\n"
	f := newFake(t, reply{503, body})
	_, stderr, code := f.run(t, "project", "rotate-key", mref, "--service")
	if code != 1 || !strings.Contains(stderr, "may still accept the old key") {
		t.Fatalf("%d %q", code, stderr)
	}
}

// Every new command keeps the contract on a 503: the body alone on stdout,
// exit 1; a usage error is 2 with nothing on stdout.
func TestReview_CLI_Contract(t *testing.T) {
	body := `{"code":"not_in_force","message":"committed; not yet in force: dashboard file: x","issuer":"i","client_id":"c",` +
		`"authorize_url":"https://a","end_session_url":"","session_seconds":300,"kids":["k"],"updated_at":"2026-11-19T10:00:00Z","dashboard_generation":null}` + "\n"
	f := newFake(t, reply{503, body})
	if out, _, code := f.run(t, "member", "add", mref, "--subject", "a", "--role", "owner"); code != 1 || out != body {
		t.Fatalf("%d %q", code, out)
	}
	for _, args := range [][]string{
		{"member", "remove", mref},
		{"member", "remove", mref, "--subject", "a", "--keep-service-key", "--rotate-service-key"},
		{"dashboard", "revoke", "only-one"},
		{"project", "rotate-key", mref},
		{"project", "audit", mref, "--tail", "x"},
		{"dashboard", "issuer", "set", "--issuer", "i"},
	} {
		f := newFake(t, reply{200, "{}\n"})
		out, _, code := f.run(t, args...)
		if code != 2 || out != "" || len(f.requests()) != 0 {
			t.Fatalf("%q: %d %q", args, code, out)
		}
	}
}

// A revocation not in force never says that sessions are refused.
func TestReview_CLI_RevokeNotInForce_NoRefusedLine(t *testing.T) {
	body := `{"code":"not_in_force","message":"committed; not yet in force: dashboard file: disk full","issuer":"i","subject":"s",` +
		`"not_before":"2026-11-19T10:00:00Z","dashboard_generation":null}` + "\n"
	f := newFake(t, reply{503, body})
	if _, stderr, code := f.run(t, "dashboard", "revoke", "i", "s"); code != 1 || strings.Contains(stderr, "is refused") {
		t.Fatalf("%d %q", code, stderr)
	}
}

// An owed REST reload is said; the issuer note counts the entries left out.
func TestReview_CLI_OwedSignalAndSkippedEntries(t *testing.T) {
	body := `{"ref":"` + mref + `","service_key":"rotated","rotation":{"gateway":"done","rest":"owed: signal follows"}}` + "\n"
	f := newFake(t, reply{200, body})
	if _, stderr, code := f.run(t, "project", "rotate-key", mref, "--service"); code != 0 ||
		!strings.Contains(stderr, "the REST service reloads the new one in a later round") {
		t.Fatalf("%d %q", code, stderr)
	}
	jf := t.TempDir() + "/jwks.json"
	if err := writeFile(jf, `{"keys":[{"kty":"RSA","kid":"a"},{"kty":"EC","kid":"b"},{"kty":"RSA","kid":"c","use":"enc"}]}`); err != nil {
		t.Fatal(err)
	}
	doc := `{"issuer":"i","client_id":"c","authorize_url":"https://a","end_session_url":"","session_seconds":300,"kids":["a"],` +
		`"updated_at":"2026-11-19T10:00:00Z","dashboard_generation":3}` + "\n"
	f = newFake(t, reply{200, doc})
	_, stderr, code := f.run(t, "dashboard", "issuer", "set", "--issuer", "i", "--client-id", "c", "--authorize-url", "https://a", "--jwks", jf)
	if code != 0 || !strings.Contains(stderr, "2 of the 3 entries of the key set are not RS256 signing keys") {
		t.Fatalf("%d %q", code, stderr)
	}
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }
