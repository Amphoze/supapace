package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// No fmt verb prints a stanza passphrase or a job's secrets.
func TestSpecString_NoStanzaPass(t *testing.T) {
	const pass = "stanza-pass-6f1d0c2e"
	s := Spec{Ref: "abcdefghij0123456789", Stanza: "abcdefghij0123456789-1", StanzaPass: pass, Layout: 2, RepoQuotaMB: 8192}
	j := JobSpec{ID: 3, Subject: s.Ref, Kind: "push", SecretEnv: map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": pass}, Cred: []byte(pass)}
	for _, v := range []any{s, &s, j, &j, []any{s, j}, map[string]any{"s": s, "j": j}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, pass) {
				t.Errorf("%s of %T prints the passphrase: %s", verb, v, out)
			}
		}
	}
	// Control: the same verbs on the bare map do print it, so the check can fail.
	if !strings.Contains(fmt.Sprintf("%v", j.SecretEnv), pass) {
		t.Fatal("control failed")
	}
	if out := fmt.Sprint(j); !strings.Contains(out, "push") || !strings.Contains(out, s.Ref) {
		t.Errorf("JobSpec.String lost its identity: %s", out)
	}
	// The passphrase is not encoded with the rest of a Spec.
	if b, err := json.Marshal(s); err != nil || strings.Contains(string(b), pass) {
		t.Errorf("json of Spec: %s, %v", b, err)
	}
}

// A job's secrets print through no verb, no JSON encoding and no wrapped error.
func TestJobSpec_SecretsCannotPrint(t *testing.T) {
	const pass = "job-secret-9a3c"
	j := JobSpec{ID: 3, Subject: "abcdefghij0123456789", Kind: "replicate", Env: map[string]string{"A": "b"},
		SecretEnv: map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": pass}, Cred: []byte(pass + "\n" + pass)}
	held := struct{ J JobSpec }{j}
	for _, v := range []any{j, &j, held, &held} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x", "%X"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, pass) || strings.Contains(strings.ToLower(out), fmt.Sprintf("%x", pass)) {
				t.Errorf("%s of %T prints a secret: %s", verb, v, out)
			}
		}
	}
	err := fmt.Errorf("run %v: %w", j, errors.New("exit 1"))
	if strings.Contains(err.Error(), pass) || !strings.Contains(err.Error(), "replicate") {
		t.Errorf("wrapped error: %v", err)
	}
	b, jerr := json.Marshal(j)
	if jerr != nil || strings.Contains(string(b), pass) || strings.Contains(string(b), "am9i") || !strings.Contains(string(b), `"Kind":"replicate"`) {
		t.Errorf("json of JobSpec: %s, %v", b, jerr)
	}
	// Control: without the method, a reflection print of the same values shows the secret.
	type bare JobSpec
	if !strings.Contains(fmt.Sprintf("%v", bare(j)), pass) {
		t.Fatal("control failed")
	}
}
