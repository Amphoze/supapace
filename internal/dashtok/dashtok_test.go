package dashtok

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the refused cases of testdata/vectors.json")

type vecToken struct {
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Payload string `json:"payload"`
	Token   string `json:"token"`
	Now     int64  `json:"now"`
}

type vecRefused struct {
	Kind  string `json:"kind"`
	Case  string `json:"case"`
	Token string `json:"token"`
	Now   int64  `json:"now"`
	Error string `json:"error"`
}

type vecFile struct {
	Comment           string            `json:"comment"`
	SeedHex           string            `json:"seed_hex"`
	PrivateFile       string            `json:"private_file"`
	PublicFile        string            `json:"public_file"`
	Node              string            `json:"node"`
	SessionMaxSeconds int64             `json:"session_max_seconds"`
	Login             map[string]string `json:"login"`
	Tokens            []vecToken        `json:"tokens"`
	Refused           []vecRefused      `json:"refused"`
}

const vecPath = "testdata/vectors.json"

func loadVectors(t *testing.T) vecFile {
	t.Helper()
	b, err := os.ReadFile(vecPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vecFile
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func vecKeys(t *testing.T, v vecFile) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	priv, err := ParsePrivate([]byte(v.PrivateFile))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublic([]byte(v.PublicFile))
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

var errNames = map[string]error{
	"ErrMalformed": ErrMalformed, "ErrSignature": ErrSignature, "ErrExpired": ErrExpired,
	"ErrNotYet": ErrNotYet, "ErrLifetime": ErrLifetime, "ErrNode": ErrNode, "ErrField": ErrField,
}

// verify runs the verifier of kind against token with the file's node and
// session bound, and returns the decoded value.
func verify(kind string, pub ed25519.PublicKey, token, node string, maxSeconds int64, now time.Time) (any, error) {
	switch kind {
	case "assertion":
		return VerifyAssertion(pub, token, node, now)
	case "session":
		return VerifySession(pub, token, maxSeconds, now)
	case "ticket":
		return VerifyTicket(pub, token, now)
	}
	panic("kind " + kind)
}

// decoded unmarshals a vector's payload with the standard decoder into the
// struct of its kind, independently of the package's own parser.
func decoded(t *testing.T, kind, payload string) any {
	t.Helper()
	var err error
	var v any
	switch kind {
	case "assertion":
		var a Assertion
		err = json.Unmarshal([]byte(payload), &a)
		v = a
	case "session":
		var s Session
		err = json.Unmarshal([]byte(payload), &s)
		v = s
	case "ticket":
		var tk Ticket
		err = json.Unmarshal([]byte(payload), &tk)
		v = tk
	}
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func equal(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// The four values the format's description fixes, spelled out here so that
// an edit of the file cannot move them unnoticed.
const (
	wantPrivate   = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	wantPublic    = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
	wantAssertion = "v1.eyJub2RlIjoibG9jYWwiLCJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0Iiwic3ViIjoidXNlci0xIiwibmFtZSI6IkFkYSIsInJlZiI6ImFiY2RlZmdoaWowMTIzNDU2Nzg5Iiwicm9sZSI6Im93bmVyIiwicHVycG9zZSI6IiIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDMwfQ.u-NX6bjeGRKmR--hl925dkQF5L7xolUDIL8IutaHHDCM6Bro_nbKj2SLogjhJNIpFWCN9tYXjYm7E0cEslruCQ"
	wantSession   = "v1.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0Iiwic3ViIjoidXNlci0xIiwibmFtZSI6IkFkYSIsInJlZiI6ImFiY2RlZmdoaWowMTIzNDU2Nzg5IiwiaWF0IjoxODAwMDAwMDAwLCJleHAiOjE4MDAwMjg4MDB9.yKaMO7c58uqlh301A_Ww5vuECs9uP4mpBbgtH_Wqd4VOg9H_D6OOrXtfl5Ojte-1zRV2AovaZ_5NnrYo_WIHBw"
	wantTicket    = "v1.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0Iiwic3ViIjoidXNlci0xIiwicmVmcyI6WyJhYmNkZWZnaGlqMDEyMzQ1Njc4OSIsImJjZGVmZ2hpajAxMjM0NTY3ODlhIl0sIm1vcmUiOmZhbHNlLCJpYXQiOjE4MDAwMDAwMDAsImV4cCI6MTgwMDAwMDA2MH0._twk6vOk39Ukg4_cltvF3UvSglLnsFJ5G3PPGxyEWs6vtRG_RZKki4Mdv8dxAiG1-9MlebgAkTLHX9Ly-_L8Dg"
	// The same ticket with "more" true.
	wantTicketMore = "v1.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0Iiwic3ViIjoidXNlci0xIiwicmVmcyI6WyJhYmNkZWZnaGlqMDEyMzQ1Njc4OSIsImJjZGVmZ2hpajAxMjM0NTY3ODlhIl0sIm1vcmUiOnRydWUsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDYwfQ.FzJMQqoZVmU_zNwNyPult2o0eT3fW1Nl7yMkBH0ubs-8y_3CE-iQJyOWK0-kep4nO-DQ6piMnloWKfYMgmVKDA"
	// The ticket of the five-member format, validly signed: refused since
	// the member "more" is required.
	oldTicket = "v1.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0Iiwic3ViIjoidXNlci0xIiwicmVmcyI6WyJhYmNkZWZnaGlqMDEyMzQ1Njc4OSIsImJjZGVmZ2hpajAxMjM0NTY3ODlhIl0sImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDYwfQ.QEl0ba6GAYbQ6effdDziYy-qPSMm2P6o01VS19DNzM5k8dfMMud0WhosA9U4ZdNkmRQtLn7Kk1bKMW4Lb728Ag"

	// A further assertion whose name holds <, >, &, a quote, a backslash and
	// non-ASCII text: another implementation must re-serialise it to these bytes.
	wantAssertionName = "v1.eyJub2RlIjoibG9jYWwiLCJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0Iiwic3ViIjoidXNlci0xIiwibmFtZSI6Ilpvw6sgPGI-JlwiXFwg5pel5pys6KqeIiwicmVmIjoiYWJjZGVmZ2hpajAxMjM0NTY3ODkiLCJyb2xlIjoib3duZXIiLCJwdXJwb3NlIjoiIiwiaWF0IjoxODAwMDAwMDAwLCJleHAiOjE4MDAwMDAwMzB9.spXtOlH9pOEDwgDiaXnc0UcxQS0XgesrpXG3xjn1_PadMSamXqPZCv2P5AeI-9ECcN-UJE9ZhUlTXVPl9feZDw"

	wantNonce = "6oZqdX5MOLq_qBJ8vppAnT4fk6AP8UiP9zX8-Rev_9A"
)

func TestVectors_SignGivesExactlyTheVector(t *testing.T) {
	v := loadVectors(t)
	if v.PrivateFile != wantPrivate || v.PublicFile != wantPublic {
		t.Fatal("key files in the vector file differ from the fixed ones")
	}
	seed, _ := hex.DecodeString(v.SeedHex)
	priv, pub := vecKeys(t, v)
	if !bytes.Equal(priv.Seed(), seed) || !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		t.Fatal("private file, public file and seed disagree")
	}
	// In file order: the ticket twice, "more" false and then true; then the
	// assertion with the name of many characters.
	want := []string{wantAssertion, wantSession, wantTicket, wantTicketMore, wantAssertionName}
	kinds := []string{"assertion", "session", "ticket", "ticket", "assertion"}
	labels := map[string]string{"assertion": "supapace-assertion-v1.", "session": "supapace-session-v1.", "ticket": "supapace-logout-v1."}
	if len(v.Tokens) != len(want) {
		t.Fatalf("%d tokens, want %d", len(v.Tokens), len(want))
	}
	for i, tc := range v.Tokens {
		if tc.Kind != kinds[i] || tc.Token != want[i] || tc.Label != labels[tc.Kind] {
			t.Fatalf("token %d (%s): vector file kind, token or label differs from the fixed one", i, tc.Kind)
		}
		if p := strings.Split(tc.Token, ".")[1]; base64.RawURLEncoding.EncodeToString([]byte(tc.Payload)) != p {
			t.Fatalf("%s: payload does not encode to the token's", tc.Kind)
		}
		var got string
		var err error
		switch x := decoded(t, tc.Kind, tc.Payload).(type) {
		case Assertion:
			got, err = SignAssertion(priv, x)
		case Session:
			got, err = SignSession(priv, x)
		case Ticket:
			got, err = SignTicket(priv, x)
		}
		if err != nil || got != tc.Token {
			t.Errorf("%s: Sign = %q, %v\nwant %q", tc.Kind, got, err, tc.Token)
		}
	}
	sum := sha256.Sum256([]byte(v.Login["r"]))
	if v.Login["r"] != wantPrivate || v.Login["nonce"] != wantNonce || base64.RawURLEncoding.EncodeToString(sum[:]) != wantNonce {
		t.Error("login vector: nonce is not the SHA-256 of R")
	}
}

func TestVectors_VerifyAccepts(t *testing.T) {
	v := loadVectors(t)
	_, pub := vecKeys(t, v)
	for _, tc := range v.Tokens {
		got, err := verify(tc.Kind, pub, tc.Token, v.Node, v.SessionMaxSeconds, time.Unix(tc.Now, 0))
		if err != nil {
			t.Errorf("%s: %v", tc.Kind, err)
			continue
		}
		if want := decoded(t, tc.Kind, tc.Payload); !equal(got, want) {
			t.Errorf("%s: got %+v, want %+v", tc.Kind, got, want)
		}
	}
}

// requiredCases are the refused cases every kind's list must carry; node only
// for the assertion.
var requiredCases = []string{
	"label-other-1", "label-other-2", "signature-bit", "exp-at-now", "exp-before-now",
	"lifetime-plus-one", "iat-six-ahead", "member-added", "member-removed", "member-duplicated",
	"members-reordered", "white-space", "padded-segment", "fourth-segment", "size-4097", "size-4096",
	"wrong-type", "version",
	"signature-trailing-bits", "signature-s-plus-l", "signature-line-end", "standard-alphabet",
}

func TestVerify_RefusesEveryListedCase(t *testing.T) {
	v := loadVectors(t)
	_, pub := vecKeys(t, v)
	seen := map[string]bool{}
	for _, rc := range v.Refused {
		want, ok := errNames[rc.Error]
		if !ok {
			t.Fatalf("%s/%s: unknown error %q", rc.Kind, rc.Case, rc.Error)
		}
		seen[rc.Kind+"/"+rc.Case] = true
		if _, err := verify(rc.Kind, pub, rc.Token, v.Node, v.SessionMaxSeconds, time.Unix(rc.Now, 0)); !errors.Is(err, want) {
			t.Errorf("%s/%s: got %v, want %v", rc.Kind, rc.Case, err, want)
		}
	}
	for _, kind := range []string{"assertion", "session", "ticket"} {
		cases := requiredCases
		switch kind {
		case "assertion":
			cases = append(cases[:len(cases):len(cases)], "node")
		case "ticket":
			cases = append(cases[:len(cases):len(cases)], "more-missing", "more-null", "more-zero", "more-string", "more-after-iat")
		}

		for _, c := range cases {
			if !seen[kind+"/"+c] {
				t.Errorf("vector file lacks %s/%s", kind, c)
			}
		}
	}
}

func TestVerify_NoKindPassesAsAnother(t *testing.T) {
	v := loadVectors(t)
	_, pub := vecKeys(t, v)
	n := 0
	for _, tc := range v.Tokens {
		for _, other := range []string{"assertion", "session", "ticket"} {
			_, err := verify(other, pub, tc.Token, v.Node, v.SessionMaxSeconds, time.Unix(tc.Now, 0))
			if other == tc.Kind {
				if err != nil {
					t.Errorf("control %s: %v", other, err)
				}
				continue
			}
			n++
			if !errors.Is(err, ErrSignature) {
				t.Errorf("%s as %s: got %v, want ErrSignature", tc.Kind, other, err)
			}
		}
	}
	if n != 10 { // two other kinds for each of the five tokens
		t.Fatalf("%d cross checks", n)
	}
}

// Fixtures for the tests below, signed with the vector key.
var (
	vPriv = ed25519.NewKeyFromSeed(func() []byte { b, _ := base64.RawURLEncoding.DecodeString(wantPrivate); return b }())
	vPub  = vPriv.Public().(ed25519.PublicKey)
	t0    = int64(1_800_000_000)
)

const ref1, ref2 = "abcdefghij0123456789", "bcdefghij0123456789a"

func baseAssertion() Assertion {
	return Assertion{Node: "local", Iss: "https://issuer.test", Sub: "user-1", Name: "Ada", Ref: ref1,
		Role: "owner", Purpose: "", Iat: t0, Exp: t0 + 30}
}

func baseSession() Session {
	return Session{Iss: "https://issuer.test", Sub: "user-1", Name: "Ada", Ref: ref1, Iat: t0, Exp: t0 + 28800}
}

func baseTicket() Ticket {
	return Ticket{Iss: "https://issuer.test", Sub: "user-1", Refs: []string{ref1, ref2}, Iat: t0, Exp: t0 + 60}
}

// signRaw signs payload exactly as given under label, bypassing every check
// of the package, so tests can build tokens the signers never produce.
func signRaw(label, payload string) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return "v1." + p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(vPriv, []byte(label+p)))
}

func at(s int64) time.Time { return time.Unix(s, 0) }

func TestAssertion_LifetimeSkewAndNode(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Assertion)
		now  int64
		node string
		want error
	}{
		{"control", nil, t0, "local", nil},
		{"lifetime 60", func(a *Assertion) { a.Exp = a.Iat + 60 }, t0, "local", nil},
		{"lifetime 61", func(a *Assertion) { a.Exp = a.Iat + 61 }, t0, "local", ErrLifetime},
		{"exp equals iat", func(a *Assertion) { a.Iat = t0 + 2; a.Exp = t0 + 2 }, t0, "local", ErrLifetime},
		{"exp before iat", func(a *Assertion) { a.Iat = t0 + 4; a.Exp = t0 + 2 }, t0, "local", ErrLifetime},
		{"iat far in the past wraps", func(a *Assertion) { a.Iat = math.MinInt64 }, t0, "local", ErrLifetime},
		{"iat now+5", func(a *Assertion) { a.Iat = t0 + 5; a.Exp = t0 + 35 }, t0, "local", nil},
		{"iat now+6", func(a *Assertion) { a.Iat = t0 + 6; a.Exp = t0 + 36 }, t0, "local", ErrNotYet},
		{"exp now+1", nil, t0 + 29, "local", nil},
		{"exp now", nil, t0 + 30, "local", ErrExpired},
		{"another node", nil, t0, "local2", ErrNode},
		{"empty verifier node", nil, t0, "", ErrNode},
		{"purpose reveal", func(a *Assertion) { a.Purpose = "reveal" }, t0, "local", nil},
		{"role developer", func(a *Assertion) { a.Role = "developer" }, t0, "local", nil},
		{"role read_only", func(a *Assertion) { a.Role = "read_only" }, t0, "local", nil},
	}
	for _, c := range cases {
		a := baseAssertion()
		if c.mod != nil {
			c.mod(&a)
		}
		tok, err := SignAssertion(vPriv, a)
		if err != nil {
			t.Fatalf("%s: sign: %v", c.name, err)
		}
		got, err := VerifyAssertion(vPub, tok, c.node, at(c.now))
		if !errors.Is(err, c.want) || (err == nil) != (c.want == nil) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		if err == nil && !equal(got, a) {
			t.Errorf("%s: got %+v", c.name, got)
		}
		if err != nil && !equal(got, Assertion{}) {
			t.Errorf("%s: refused verify returned a value", c.name)
		}
	}
	// Values outside a member's domain are refused by the signer and, signed
	// anyway, by the verifier.
	for name, mod := range map[string]func(*Assertion){
		"role admin":       func(a *Assertion) { a.Role = "admin" },
		"role Owner":       func(a *Assertion) { a.Role = "Owner" },
		"purpose other":    func(a *Assertion) { a.Purpose = "write" },
		"ref short":        func(a *Assertion) { a.Ref = "abc" },
		"ref upper":        func(a *Assertion) { a.Ref = "ABCDEFGHIJ0123456789" },
		"ref apex":         func(a *Assertion) { a.Ref = "_" },
		"node empty":       func(a *Assertion) { a.Node = "" },
		"node control":     func(a *Assertion) { a.Node = "lo\ncal" },
		"node 256":         func(a *Assertion) { a.Node = strings.Repeat("n", 256) },
		"iss empty":        func(a *Assertion) { a.Iss = "" },
		"sub non-ascii":    func(a *Assertion) { a.Sub = "usér" },
		"name control":     func(a *Assertion) { a.Name = "A\u0085da" },
		"name 129":         func(a *Assertion) { a.Name = strings.Repeat("a", 129) },
		"name bad utf-8":   func(a *Assertion) { a.Name = "A\xffda" },
		"sub del":          func(a *Assertion) { a.Sub = "user\x7f" },
		"iss 256":          func(a *Assertion) { a.Iss = strings.Repeat("i", 256) },
		"sub tab":          func(a *Assertion) { a.Sub = "user\t1" },
		"node bad utf-8":   func(a *Assertion) { a.Node = "lo\xffcal" },
		"name U+2028":      func(a *Assertion) { a.Name = "A\u2028da" },
		"name U+2029":      func(a *Assertion) { a.Name = "A\u2029da" },
		"node U+2028":      func(a *Assertion) { a.Node = "lo\u2028cal" },
		"name 128 is fine": nil,
	} {
		a := baseAssertion()
		if mod == nil {
			a.Name = strings.Repeat("é", 64) // 128 bytes
			if _, err := SignAssertion(vPriv, a); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		mod(&a)
		if _, err := SignAssertion(vPriv, a); !errors.Is(err, ErrField) {
			t.Errorf("%s: sign got %v, want ErrField", name, err)
		}
		if !utf8Valid(a) {
			continue // the standard encoder would replace the bytes; covered by the strict-payload test
		}
		p, _ := json.Marshal(a)
		if _, err := VerifyAssertion(vPub, signRaw(assertionLabel, string(p)), "local", at(t0)); !errors.Is(err, ErrField) {
			t.Errorf("%s: verify got %v, want ErrField", name, err)
		}
	}
}

func utf8Valid(a Assertion) bool {
	p, _ := json.Marshal(a)
	return !bytes.Contains(p, []byte(`�`))
}

func TestSession_MaxSeconds(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Session)
		max  int64
		want error
	}{
		{"exactly the bound", nil, 28800, nil},
		{"one above", nil, 28799, ErrLifetime},
		{"zero bound", nil, 0, ErrLifetime},
		{"negative bound", nil, -1, ErrLifetime},
		{"most negative bound", nil, math.MinInt64, ErrLifetime},
		{"apex", func(s *Session) { s.Ref = "_" }, 28800, nil},
		{"exp equals iat", func(s *Session) { s.Iat = t0 + 1; s.Exp = t0 + 1 }, 28800, ErrLifetime},
		{"iat far in the past wraps", func(s *Session) { s.Iat = math.MinInt64 }, math.MaxInt64, ErrLifetime},
		{"huge bound", nil, math.MaxInt64, nil},
		{"iat now+6", func(s *Session) { s.Iat = t0 + 6 }, 28800, ErrNotYet},
		{"exp now", func(s *Session) { s.Iat = t0 - 100; s.Exp = t0 }, 28800, ErrExpired},
	}
	for _, c := range cases {
		s := baseSession()
		if c.mod != nil {
			c.mod(&s)
		}
		tok, err := SignSession(vPriv, s)
		if err != nil {
			t.Fatalf("%s: sign: %v", c.name, err)
		}
		got, err := VerifySession(vPub, tok, c.max, at(t0))
		if !errors.Is(err, c.want) || (err == nil) != (c.want == nil) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		if err == nil && !equal(got, s) {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
	for _, ref := range []string{"__", "", "-", ref1 + "a"} {
		s := baseSession()
		s.Ref = ref
		if _, err := SignSession(vPriv, s); !errors.Is(err, ErrField) {
			t.Errorf("ref %q: %v", ref, err)
		}
		p, _ := json.Marshal(s)
		if _, err := VerifySession(vPub, signRaw(sessionLabel, string(p)), 28800, at(t0)); !errors.Is(err, ErrField) {
			t.Errorf("ref %q: verify %v", ref, err)
		}
	}
}

func refsN(n int) []string {
	r := make([]string, n)
	for i := range r {
		r[i] = strings.Repeat("a", 18) + strconv.Itoa(10+i)
	}
	return r
}

func TestTicket_AtMostSixteenRefs(t *testing.T) {
	for _, c := range []struct {
		name string
		refs []string
		want error
	}{
		{"one", refsN(1), nil},
		{"sixteen", refsN(16), nil},
		{"seventeen", refsN(17), ErrField},
		{"none", []string{}, ErrField},
		{"null", nil, ErrField},
		{"the sign-in host is not a hop", []string{ref1, "_"}, ErrField},
		{"bad ref", []string{"ABCDEFGHIJ0123456789"}, ErrField},
	} {
		tk := baseTicket()
		tk.Refs = c.refs
		tok, err := SignTicket(vPriv, tk)
		if !errors.Is(err, c.want) || (err == nil) != (c.want == nil) {
			t.Errorf("%s: sign got %v, want %v", c.name, err, c.want)
		}
		if err != nil {
			p, _ := json.Marshal(tk)
			tok = signRaw(logoutLabel, string(p))
		}
		got, err := VerifyTicket(vPub, tok, at(t0))
		if !errors.Is(err, c.want) || (err == nil) != (c.want == nil) {
			t.Errorf("%s: verify got %v, want %v", c.name, err, c.want)
		}
		if err == nil && !equal(got, tk) {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
	for _, c := range []struct {
		name     string
		iat, exp int64
		want     error
	}{
		{"lifetime 60", t0, t0 + 60, nil},
		{"lifetime 61", t0, t0 + 61, ErrLifetime},
		{"iat now+6", t0 + 6, t0 + 20, ErrNotYet},
		{"exp now", t0 - 10, t0, ErrExpired},
		{"exp before iat", t0 + 3, t0 + 1, ErrLifetime},
	} {
		tk := baseTicket()
		tk.Iat, tk.Exp = c.iat, c.exp
		tok, err := SignTicket(vPriv, tk)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyTicket(vPub, tok, at(t0)); !errors.Is(err, c.want) || (err == nil) != (c.want == nil) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// TestTicket_MoreIsRequiredAndKept: the ticket's "more" is a boolean, always
// present, between refs and iat. Both values round-trip and give the two
// fixed vectors; a payload without it, with a further member, with anything
// but true or false there, or with it out of its place is refused.
func TestTicket_MoreIsRequiredAndKept(t *testing.T) {
	for more, want := range map[bool]string{false: wantTicket, true: wantTicketMore} {
		tk := baseTicket()
		tk.More = more
		tok, err := SignTicket(vPriv, tk)
		if err != nil || tok != want {
			t.Fatalf("more %v: Sign = %q, %v\nwant %q", more, tok, err, want)
		}
		got, err := VerifyTicket(vPub, tok, at(t0+10))
		if err != nil || got.More != more || !equal(got, tk) {
			t.Fatalf("more %v: Verify = %+v, %v", more, got, err)
		}
	}
	const good = `{"iss":"https://issuer.test","sub":"user-1","refs":["abcdefghij0123456789","bcdefghij0123456789a"],"more":false,"iat":1800000000,"exp":1800000060}`
	if tok := signRaw(logoutLabel, good); tok != wantTicket {
		t.Fatalf("control: the payload does not sign to the vector: %q", tok)
	}
	if _, err := VerifyTicket(vPub, oldTicket, at(t0+10)); !errors.Is(err, ErrField) {
		t.Errorf("the five-member ticket under a valid signature: got %v, want ErrField", err)
	}
	const refs = `"refs":["abcdefghij0123456789","bcdefghij0123456789a"]`
	for name, payload := range map[string]string{
		"without more":    strings.Replace(good, `"more":false,`, "", 1),
		"a seventh":       strings.Replace(good, `}`, `,"all":true}`, 1),
		"more null":       strings.Replace(good, `"more":false`, `"more":null`, 1),
		"more 0":          strings.Replace(good, `"more":false`, `"more":0`, 1),
		"more 1":          strings.Replace(good, `"more":false`, `"more":1`, 1),
		"more a string":   strings.Replace(good, `"more":false`, `"more":"true"`, 1),
		"more after iat":  strings.Replace(good, `"more":false,"iat":1800000000`, `"iat":1800000000,"more":false`, 1),
		"more before":     strings.Replace(good, refs+`,"more":false`, `"more":false,`+refs, 1),
		"more twice":      strings.Replace(good, `"more":false`, `"more":false,"more":false`, 1),
		"more, then true": strings.Replace(good, `"more":false`, `"more":false,"more":true`, 1),
		"More":            strings.Replace(good, `"more"`, `"More"`, 1),
		"more capital":    strings.Replace(good, `"more":false`, `"more":False`, 1),
	} {
		if payload == good {
			t.Fatalf("%s: the case changes nothing", name)
		}
		_, err := VerifyTicket(vPub, signRaw(logoutLabel, payload), at(t0+10))
		want := ErrField
		if name == "more capital" { // not JSON
			want = ErrMalformed
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", name, err, want)
		}
	}
}

func TestPayload_StrictMembersAndOrder(t *testing.T) {
	const good = `{"iss":"https://issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`
	if _, err := VerifySession(vPub, signRaw(sessionLabel, good), 28800, at(t0)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, c := range map[string]struct {
		payload string
		want    error
	}{
		"unknown member":          {`{"iss":"https://issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800,"role":"owner"}`, ErrField},
		"missing member":          {`{"iss":"https://issuer.test","sub":"user-1","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrField},
		"duplicate member":        {`{"iss":"https://issuer.test","sub":"user-1","name":"Ada","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrField},
		"duplicate, last differs": {`{"iss":"https://issuer.test","sub":"user-0","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrField},
		"reordered":               {`{"sub":"user-1","iss":"https://issuer.test","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrField},
		"name in other case":      {`{"iss":"https://issuer.test","Sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrField},
		"wrong type":              {`{"iss":"https://issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":"1800000000","exp":1800028800}`, ErrField},
		"null member":             {`{"iss":"https://issuer.test","sub":"user-1","name":null,"ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrField},
		"escaped character":       {`{"iss":"https://issuer.test","sub":"user-1","name":"\u0041da","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrField},
		"escaped slash":           {`{"iss":"https:\/\/issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrField},
		"fraction":                {`{"iss":"https://issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000.0,"exp":1800028800}`, ErrField},
		"exponent":                {`{"iss":"https://issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":18e8,"exp":1800028800}`, ErrField},
		"bad utf-8":               {"{\"iss\":\"https://issuer.test\",\"sub\":\"user-1\",\"name\":\"A\xffda\",\"ref\":\"abcdefghij0123456789\",\"iat\":1800000000,\"exp\":1800028800}", ErrField},
		"null":                    {`null`, ErrField},
		"array":                   {`[]`, ErrField},
		"string":                  {`"x"`, ErrField},
		"white space":             {`{"iss": "https://issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`, ErrMalformed},
		"trailing new line":       {good + "\n", ErrMalformed},
		"trailing value":          {good + `{}`, ErrMalformed},
		"truncated":               {good[:len(good)-1], ErrMalformed},
		"empty":                   {``, ErrMalformed},
		// Names the standard decoder matches without regard to case or by
		// Unicode folding, and duplicates it would resolve to the last.
		"name folded, long s":     {strings.Replace(good, `"sub"`, "\"\u017fub\"", 1), ErrField},
		"name folded, kelvin":     {strings.Replace(good, `"ref"`, "\"\u212aef\"", 1), ErrField},
		"name escaped":            {strings.Replace(good, `"sub"`, `"\u0073ub"`, 1), ErrField},
		"duplicate in other case": {strings.Replace(good, `"sub":"user-1"`, `"sub":"user-1","SUB":"user-2"`, 1), ErrField},
		"negative zero":           {strings.Replace(good, `"iat":1800000000`, `"iat":-0`, 1), ErrField},
		"leading zero":            {strings.Replace(good, `"iat":1800000000`, `"iat":01800000000`, 1), ErrMalformed},
		"beyond int64":            {strings.Replace(good, `"iat":1800000000`, `"iat":9223372036854775808`, 1), ErrField},
		"byte order mark":         {"\xef\xbb\xbf" + good, ErrMalformed},
		"deep nesting":            {strings.Replace(good, `"Ada"`, strings.Repeat("[", 1000)+strings.Repeat("]", 1000), 1), ErrField},
		"escaped NUL":             {strings.Replace(good, `"Ada"`, `"A\u0000da"`, 1), ErrField},
		"escaped lone surrogate":  {strings.Replace(good, `"Ada"`, `"A\ud800da"`, 1), ErrField},
		"escaped markup":          {strings.Replace(good, `"Ada"`, `"A\u003cda"`, 1), ErrField},
	} {
		if _, err := VerifySession(vPub, signRaw(sessionLabel, c.payload), 28800, at(t0)); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	// A display name with characters the HTML-escaping encoder would rewrite
	// signs and verifies as itself.
	s := baseSession()
	s.Name = `<b>&"x"</b>`
	tok, err := SignSession(vPriv, s)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifySession(vPub, tok, 28800, at(t0)); err != nil || got.Name != s.Name {
		t.Fatalf("name round trip: %+v %v", got, err)
	}
	p, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if !bytes.Contains(p, []byte(`"name":"<b>&\"x\"</b>"`)) {
		t.Fatalf("payload %s", p)
	}
}

func TestKeyFiles_RoundTrip(t *testing.T) {
	privFile, pubFile, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range [][]byte{privFile, pubFile} {
		if len(f) != 44 || f[43] != '\n' || bytes.Count(f, []byte("\n")) != 1 {
			t.Fatalf("file %q is not one line of 43 characters", f)
		}
	}
	priv, err := ParsePrivate(privFile)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublic(pubFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		t.Fatal("public file is not the private key's")
	}
	tok, err := SignAssertion(priv, baseAssertion())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAssertion(pub, tok, "local", at(t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAssertion(vPub, tok, "local", at(t0)); !errors.Is(err, ErrSignature) {
		t.Fatalf("another key: %v", err)
	}
	// The fixed files parse with and without their line end.
	for _, f := range []string{wantPrivate, wantPrivate + "\n"} {
		if k, err := ParsePrivate([]byte(f)); err != nil || !bytes.Equal(k, vPriv) {
			t.Errorf("%q: %v", f, err)
		}
	}
	if k, err := ParsePublic([]byte(wantPublic + "\n")); err != nil || !bytes.Equal(k, vPub) {
		t.Errorf("public: %v", err)
	}
	for _, f := range []string{
		"", "\n", wantPrivate + "\n\n", wantPrivate + "\r\n", wantPrivate[:42], wantPrivate + "A",
		wantPrivate + "=", " " + wantPrivate, strings.Replace(wantPrivate, "A", "+", 1),
		wantPrivate[:42] + "h", // non-zero trailing bits
		strings.Repeat("A", 86),
		wantPrivate[:20] + "\r\n\r" + wantPrivate[20:40], // 43 characters, three of which the decoder skips
	} {
		if _, err := ParsePrivate([]byte(f)); !errors.Is(err, ErrMalformed) {
			t.Errorf("private %q: %v", f, err)
		}
		if _, err := ParsePublic([]byte(f)); !errors.Is(err, ErrMalformed) {
			t.Errorf("public %q: %v", f, err)
		}
	}
}

func TestKeys_WrongSizeNeverPanics(t *testing.T) {
	if _, err := SignAssertion(ed25519.PrivateKey(make([]byte, 31)), baseAssertion()); err == nil {
		t.Error("short private key signed")
	}
	if _, err := SignSession(nil, baseSession()); err == nil {
		t.Error("nil private key signed")
	}
	if _, err := SignTicket(nil, baseTicket()); err == nil {
		t.Error("nil private key signed")
	}
	tok, _ := SignAssertion(vPriv, baseAssertion())
	for _, k := range []ed25519.PublicKey{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := VerifyAssertion(k, tok, "local", at(t0)); !errors.Is(err, ErrSignature) {
			t.Errorf("key of %d bytes: %v", len(k), err)
		}
	}
}

func TestVerify_EnvelopeShapes(t *testing.T) {
	tok, _ := SignAssertion(vPriv, baseAssertion())
	seg := strings.Split(tok, ".")
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 63))
	for name, s := range map[string]string{
		"empty":                    "",
		"no dots":                  "v1",
		"one dot":                  "v1." + seg[1],
		"empty payload":            "v1.." + seg[2],
		"empty signature":          "v1." + seg[1] + ".",
		"short signature":          "v1." + seg[1] + "." + short,
		"long signature":           "v1." + seg[1] + "." + seg[2] + "AA",
		"signature trailing bits":  "v1." + seg[1] + "." + seg[2][:85] + "D",
		"signature with line ends": "v1." + seg[1] + "." + seg[2][:84] + "\r\n",
		"upper version":            "V1." + seg[1] + "." + seg[2],
		"no version":               seg[1] + "." + seg[2],
		"standard alphabet":        "v1." + seg[1] + "." + strings.NewReplacer("-", "+", "_", "/").Replace(seg[2]),
		"line break":               "v1." + seg[1][:10] + "\n" + seg[1][10:] + "." + seg[2],
		"space":                    "v1. " + seg[1] + "." + seg[2],
	} {
		if s == tok {
			t.Fatalf("%s: equals the control", name)
		}
		if _, err := VerifyAssertion(vPub, s, "local", at(t0)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
	if _, err := VerifyAssertion(vPub, tok, "local", at(t0)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// TestVectors_UpdateRefused rewrites the refused cases of the vector file
// when run with -update. The accepted tokens are kept as they are: they are
// the fixed contract and are never regenerated.
func TestVectors_UpdateRefused(t *testing.T) {
	if !*update {
		t.Skip("run with -update to rewrite the refused cases")
	}
	v := loadVectors(t)
	v.Refused = nil
	labels := map[string]string{"assertion": assertionLabel, "session": sessionLabel, "ticket": logoutLabel}
	done := map[string]bool{}
	for _, tc := range v.Tokens {
		if done[tc.Kind] { // the cases derive from each kind's first token
			continue
		}
		done[tc.Kind] = true
		label := labels[tc.Kind]
		add := func(c, tok string, now int64, e string) {
			v.Refused = append(v.Refused, vecRefused{Kind: tc.Kind, Case: c, Token: tok, Now: now, Error: e})
		}
		var m []kv
		if err := orderedMembers(tc.Payload, &m); err != nil {
			t.Fatal(err)
		}
		get := func(k string) int64 {
			for _, x := range m {
				if x.k == k {
					n, _ := strconv.ParseInt(x.v, 10, 64)
					return n
				}
			}
			t.Fatalf("no %s", k)
			return 0
		}
		iat, exp := get("iat"), get("exp")
		now := tc.Now
		bound := exp - iat // the vector's lifetime is its kind's bound
		if tc.Kind == "assertion" {
			bound = 60
		}
		with := func(set map[string]string) string {
			var b strings.Builder
			b.WriteByte('{')
			for i, x := range m {
				if i > 0 {
					b.WriteByte(',')
				}
				val := x.v
				if s, ok := set[x.k]; ok {
					val = s
				}
				b.WriteString(strconv.Quote(x.k) + ":" + val)
			}
			b.WriteByte('}')
			return b.String()
		}
		n := 1
		for _, other := range []string{"assertion", "session", "ticket"} {
			if other != tc.Kind {
				add("label-other-"+strconv.Itoa(n), signRaw(labels[other], tc.Payload), now, "ErrSignature")
				n++
			}
		}
		seg := strings.Split(tc.Token, ".")
		sig, _ := base64.RawURLEncoding.DecodeString(seg[2])
		sig[0] ^= 1
		add("signature-bit", "v1."+seg[1]+"."+base64.RawURLEncoding.EncodeToString(sig), now, "ErrSignature")
		add("exp-at-now", tc.Token, exp, "ErrExpired")
		add("exp-before-now", tc.Token, exp+1, "ErrExpired")
		add("lifetime-plus-one", signRaw(label, with(map[string]string{"exp": strconv.FormatInt(iat+bound+1, 10)})), now, "ErrLifetime")
		ahead := now + 6
		add("iat-six-ahead", signRaw(label, with(map[string]string{"iat": strconv.FormatInt(ahead, 10), "exp": strconv.FormatInt(ahead+exp-iat, 10)})), now, "ErrNotYet")
		if tc.Kind == "assertion" {
			add("node", signRaw(label, with(map[string]string{"node": `"other"`})), now, "ErrNode")
		}
		p := with(nil)
		add("member-added", signRaw(label, p[:len(p)-1]+`,"extra":""}`), now, "ErrField")
		add("member-removed", signRaw(label, strings.Replace(p, `"sub":"user-1",`, "", 1)), now, "ErrField")
		add("member-duplicated", signRaw(label, strings.Replace(p, `"sub":"user-1",`, `"sub":"user-1","sub":"user-1",`, 1)), now, "ErrField")
		add("members-reordered", signRaw(label, strings.Replace(p, `"iss":"https://issuer.test","sub":"user-1"`, `"sub":"user-1","iss":"https://issuer.test"`, 1)), now, "ErrField")
		add("wrong-type", signRaw(label, with(map[string]string{"iat": `"` + strconv.FormatInt(iat, 10) + `"`})), now, "ErrField")
		add("white-space", signRaw(label, strings.Replace(p, `,"sub"`, `, "sub"`, 1)), now, "ErrMalformed")
		add("padded-segment", tc.Token+"==", now, "ErrMalformed")
		add("fourth-segment", tc.Token+".AAAA", now, "ErrMalformed")
		add("version", "v2"+tc.Token[2:], now, "ErrMalformed")
		// Envelopes that a lenient base64 decoder reads as the valid token: the
		// signature's unused low bits set, a line end inside it, the standard
		// alphabet; and the signature's scalar S replaced by S + L, which a
		// verifier that does not require S < L accepts.
		last := strings.IndexByte(b64chars, seg[2][85])
		add("signature-trailing-bits", "v1."+seg[1]+"."+seg[2][:85]+string(b64chars[last|1]), now, "ErrMalformed")
		add("signature-line-end", "v1."+seg[1]+"."+seg[2][:43]+"\n"+seg[2][43:], now, "ErrMalformed")
		std := strings.NewReplacer("-", "+", "_", "/").Replace(seg[2])
		if std == seg[2] {
			t.Fatalf("%s: signature has no character the standard alphabet spells differently", tc.Kind)
		}
		add("standard-alphabet", "v1."+seg[1]+"."+std, now, "ErrMalformed")
		add("signature-s-plus-l", "v1."+seg[1]+"."+base64.RawURLEncoding.EncodeToString(plusL(t, tc.Token)), now, "ErrSignature")
		if tc.Kind != "ticket" {
			// The display name may not hold U+2028 or U+2029, written raw or
			// escaped: encoders disagree on how to write them.
			add("name-line-separator-raw", signRaw(label, strings.Replace(p, `"name":"Ada"`, "\"name\":\"A\u2028da\"", 1)), now, "ErrField")
			add("name-line-separator-escaped", signRaw(label, strings.Replace(p, `"name":"Ada"`, `"name":"A\u2028da"`, 1)), now, "ErrField")
		}
		if tc.Kind == "ticket" {
			// "more" is required, a boolean, in its place: the ticket of the
			// five-member format is refused under its valid signature.
			add("more-missing", oldTicket, now, "ErrField")
			add("more-null", signRaw(label, with(map[string]string{"more": "null"})), now, "ErrField")
			add("more-zero", signRaw(label, with(map[string]string{"more": "0"})), now, "ErrField")
			add("more-string", signRaw(label, with(map[string]string{"more": `"true"`})), now, "ErrField")
			iatText := `"iat":` + strconv.FormatInt(iat, 10)
			add("more-after-iat", signRaw(label, strings.Replace(p, `"more":false,`+iatText, iatText+`,"more":false`, 1)), now, "ErrField")
		}
		// A validly signed token of exactly 4096 bytes passes the size check
		// and is refused for its extra member; one byte more is refused first.
		for _, size := range []int{4096, 4097} {
			pad := 0
			for {
				tok := signRaw(label, p[:len(p)-1]+`,"pad":"`+strings.Repeat("x", pad)+`"}`)
				if len(tok) == size {
					e := "ErrField"
					if size > 4096 {
						e = "ErrMalformed"
					}
					add("size-"+strconv.Itoa(size), tok, now, e)
					break
				}
				if len(tok) > size { // unpadded base64 never ends at 4k+1 characters
					t.Fatalf("size %d skipped at pad %d", size, pad)
				}
				pad++
			}
		}
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vecPath, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

const b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// plusL returns token's signature with its scalar S (little-endian, the last
// 32 bytes) replaced by S + L, the order of the base point.
func plusL(t *testing.T, token string) []byte {
	t.Helper()
	sig, err := base64.RawURLEncoding.DecodeString(token[strings.LastIndexByte(token, '.')+1:])
	if err != nil || len(sig) != 64 {
		t.Fatal("signature")
	}
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	rev := func(b []byte) []byte {
		r := make([]byte, len(b))
		for i := range b {
			r[len(b)-1-i] = b[i]
		}
		return r
	}
	sum := new(big.Int).Add(new(big.Int).SetBytes(rev(sig[32:])), l).FillBytes(make([]byte, 32))
	return append(sig[:32:32], rev(sum)...)
}

type kv struct{ k, v string }

// orderedMembers splits a flat JSON object into its members in order, values
// kept as their JSON text.
func orderedMembers(s string, out *[]kv) error {
	d := json.NewDecoder(strings.NewReader(s))
	if _, err := d.Token(); err != nil {
		return err
	}
	for d.More() {
		k, err := d.Token()
		if err != nil {
			return err
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return err
		}
		*out = append(*out, kv{k.(string), string(raw)})
	}
	return nil
}

// TestSign_LargestPayloadFits: every member at its bound, with the characters
// the encoder lengthens most, still gives a token under the size limit that
// verifies — so a signer never produces a token its verifier refuses for size.
func TestSign_LargestPayloadFits(t *testing.T) {
	long := strings.Repeat("\"", 255) // one byte, written as two
	name := strings.Repeat("\\", 128)
	a := Assertion{Node: long, Iss: long, Sub: long, Name: name, Ref: ref1,
		Role: "read_only", Purpose: "reveal", Iat: math.MinInt64 + 1, Exp: math.MinInt64 + 2}
	tk := Ticket{Iss: long, Sub: long, Refs: refsN(16), More: false, Iat: math.MinInt64, Exp: math.MinInt64} // "false" is the longer value
	for _, tok := range []func() (string, error){
		func() (string, error) { return SignAssertion(vPriv, a) },
		func() (string, error) { return SignTicket(vPriv, tk) },
	} {
		s, err := tok()
		if err != nil || len(s) > maxToken {
			t.Fatalf("%d bytes, %v", len(s), err)
		}
	}
	a.Iat, a.Exp = t0, t0+60
	s, _ := SignAssertion(vPriv, a)
	if got, err := VerifyAssertion(vPub, s, a.Node, at(t0)); err != nil || got != a {
		t.Fatalf("largest assertion: %v", err)
	}
}
