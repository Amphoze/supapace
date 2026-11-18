package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/secrets"
)

// TestAPI_KeysInternalErrorsLogNoSecret walks the keys endpoint's internal
// error paths: the body is the fixed message, one sanitised log line is
// written, and neither carries key material or a credential.
func TestAPI_KeysInternalErrorsLogNoSecret(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref := "keys0000000000000000"
	e.active(t, ref)
	e.seedKeys(t, ref)
	secretsSeen := []string{"anon-token", "service-token", "pg-password", hex.EncodeToString(e.kek[:])}

	// A KEK that cannot open the DEK.
	b := logs(t)
	var wrong secrets.KEK
	rand.Read(wrong[:])
	e.h = New(e.st, wrong, e.ops, "sp.test", e.p)
	eb := e.wantCode(t, "GET", "/v1/projects/"+ref+"/keys", "", 500, "internal")
	if eb.Message != "internal error" || strings.Count(b.String(), "\n") != 1 {
		t.Fatalf("wrong KEK: message %q, log %q", eb.Message, b.String())
	}
	// A secret sealed for another name (ciphertext moved): Open fails.
	e.h = New(e.st, e.kek, e.ops, "sp.test", e.p)
	other := "move0000000000000000"
	e.active(t, other)
	dek := make([]byte, 32)
	rand.Read(dek)
	n, w, err := secrets.WrapDEK(e.kek, other, dek)
	must(t, err)
	must(t, e.st.PutDEK(ctx, other, "kek", n, w))
	for _, name := range []string{"token.anon", "token.service_role", "pg.postgres.password"} {
		nn, ct, err := secrets.Seal(dek, other, "wrong.name", []byte("pg-password"))
		must(t, err)
		must(t, e.st.PutSecret(ctx, other, name, nn, ct))
	}
	b.Reset()
	eb = e.wantCode(t, "GET", "/v1/projects/"+other+"/keys", "", 500, "internal")
	if eb.Message != "internal error" || strings.Count(b.String(), "\n") != 1 {
		t.Fatalf("moved ciphertext: message %q, log %q", eb.Message, b.String())
	}
	for _, s := range append(secretsSeen, hex.EncodeToString(dek)) {
		if strings.Contains(b.String(), s) {
			t.Fatalf("log carries %q: %q", s, b.String())
		}
	}
}

func rsaJWKS(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	must(t, err)
	return `{"keys":[{"kty":"RSA","kid":"k","n":"` + base64.RawURLEncoding.EncodeToString(k.N.Bytes()) + `","e":"AQAB"}]}`
}

// TestAPI_KeyBoundsMatchMessage pins the bounds the create message (and the
// CLI's usage text) quotes to what the token package accepts.
func TestAPI_KeyBoundsMatchMessage(t *testing.T) {
	for bits, ok := range map[int]bool{2040: false, 2048: true, 4096: true, 4104: false} {
		_, err := jwtx.ParseJWKS([]byte(rsaJWKS(t, bits)), "issuer")
		if (err == nil) != ok {
			t.Errorf("%d bits: %v", bits, err)
		}
	}
	e := newEnv(t)
	eb := e.wantCode(t, "POST", "/v1/projects", `{"name":"demo","issuer_jwks":{"keys":[]}}`, 400, "bad_request")
	for _, s := range []string{"1 to 16 RSA signing keys", "2048 to 4096 bits", "exponent 65537"} {
		if !strings.Contains(eb.Message, s) {
			t.Errorf("message lacks %q: %q", s, eb.Message)
		}
	}
	if maxIssuerKeys != 16 || minDiskQuotaMB != 1024 || maxDiskQuotaMB != 16<<20 {
		t.Fatalf("limits changed: update the create message and the CLI usage text")
	}
}

// TestAPI_KeysMessages: an unknown project and a project whose credentials
// are not issued yet are told apart.
func TestAPI_KeysMessages(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	if eb := e.wantCode(t, "GET", "/v1/projects/zzzz0000000000000000/keys", "", 404, "not_found"); eb.Message != "no such project" {
		t.Errorf("unknown project: %q", eb.Message)
	}
	if eb := e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/keys", "", 404, "not_found"); eb.Message != "the project's credentials are not issued yet" {
		t.Errorf("no DEK yet: %q", eb.Message)
	}
}
