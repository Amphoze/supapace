package dashtok

import (
	"testing"
	"time"
)

// FuzzVerify feeds arbitrary strings to the three verifiers and the two key
// file parsers: none may panic, and whatever one accepts re-signs to itself.
func FuzzVerify(f *testing.F) {
	v := []string{wantAssertion, wantSession, wantTicket, wantTicketMore, oldTicket, "", "v1..", "v1.e30." + wantTicket[len(wantTicket)-86:]}
	for _, s := range v {
		f.Add(s)
	}
	now := time.Unix(t0+10, 0)
	f.Fuzz(func(t *testing.T, s string) {
		if a, err := VerifyAssertion(vPub, s, "local", now); err == nil {
			if r, err := SignAssertion(vPriv, a); err != nil || r != s {
				t.Fatalf("accepted assertion does not re-sign to itself: %v", err)
			}
		}
		if x, err := VerifySession(vPub, s, 28800, now); err == nil {
			if r, err := SignSession(vPriv, x); err != nil || r != s {
				t.Fatalf("accepted session does not re-sign to itself: %v", err)
			}
		}
		if x, err := VerifyTicket(vPub, s, now); err == nil {
			if r, err := SignTicket(vPriv, x); err != nil || r != s {
				t.Fatalf("accepted ticket does not re-sign to itself: %v", err)
			}
		}
		_, _ = ParsePrivate([]byte(s))
		_, _ = ParsePublic([]byte(s))
	})
}

// FuzzPayload signs arbitrary payloads under each label, so that the fuzzer
// reaches the payload parser behind the signature: none may panic, and an
// accepted payload is the canonical encoding of what it decoded to.
func FuzzPayload(f *testing.F) {
	for _, s := range []string{
		`{"node":"local","iss":"https://issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","role":"owner","purpose":"","iat":1800000000,"exp":1800000030}`,
		`{"iss":"https://issuer.test","sub":"user-1","name":"Ada","ref":"abcdefghij0123456789","iat":1800000000,"exp":1800028800}`,
		`{"iss":"https://issuer.test","sub":"user-1","refs":["abcdefghij0123456789","bcdefghij0123456789a"],"more":false,"iat":1800000000,"exp":1800000060}`,
		`{"iss":"https://issuer.test","sub":"user-1","refs":["abcdefghij0123456789","bcdefghij0123456789a"],"more":true,"iat":1800000000,"exp":1800000060}`,
		`{"iss":"https://issuer.test","sub":"user-1","refs":["abcdefghij0123456789","bcdefghij0123456789a"],"iat":1800000000,"exp":1800000060}`,
		`{"iss":"https://issuer.test","\u017fub":"user-1","name":"A\u2028da","ref":"abcdefghij0123456789","iat":-0,"exp":1800028800}`,
		`{"iss":"https://issuer.test","sub":"user-1","SUB":"user-2","name":"A\ud800","ref":"abcdefghij0123456789","iat":1e9,"exp":1800028800}`,
	} {
		f.Add(s)
	}
	now := time.Unix(t0+10, 0)
	f.Fuzz(func(t *testing.T, p string) {
		if a, err := VerifyAssertion(vPub, signRaw(assertionLabel, p), "local", now); err == nil {
			if b, _ := canonical(a); string(b) != p {
				t.Fatalf("accepted a non-canonical assertion payload %q", p)
			}
		}
		if s, err := VerifySession(vPub, signRaw(sessionLabel, p), 28800, now); err == nil {
			if b, _ := canonical(s); string(b) != p {
				t.Fatalf("accepted a non-canonical session payload %q", p)
			}
		}
		if tk, err := VerifyTicket(vPub, signRaw(logoutLabel, p), now); err == nil {
			if b, _ := canonical(tk); string(b) != p {
				t.Fatalf("accepted a non-canonical ticket payload %q", p)
			}
		}
	})
}
