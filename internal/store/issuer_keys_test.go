package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/jwtx"
)

// The keys the store checked are the keys the table renders: a key set whose
// members differ only in case, or appear twice, is read by the check in one
// order and stored by the database in another.
func TestSetIssuer_KeysRenderedAreTheKeysChecked(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	good := memberTestN()
	bad := `{"kid":"k","kty":"RSA","n":"AQAB","e":"AQAB"}`
	ok := fmt.Sprintf(`{"kid":"k","kty":"RSA","n":%q,"e":"AQAB"}`, good)
	for name, jwks := range map[string]string{
		"keys then Keys":       `{"keys":[` + bad + `],"Keys":[` + ok + `]}`,
		"n then N in one key":  fmt.Sprintf(`{"keys":[{"kid":"k","kty":"RSA","n":"AQAB","N":%q,"e":"AQAB"}]}`, good),
		"kid then KID, empty":  fmt.Sprintf(`{"keys":[{"kid":"","KID":"k","kty":"RSA","n":%q,"e":"AQAB"}]}`, good),
		"kty then Kty, not RS": fmt.Sprintf(`{"keys":[{"kty":"EC","Kty":"RSA","kid":"k","n":%q,"e":"AQAB"}]}`, good),
	} {
		t.Run(name, func(t *testing.T) {
			d := memberIssuer()
			d.JWKS = json.RawMessage(jwks)
			err := s.SetDashboardIssuer(ctx, d)
			if errors.Is(err, ErrConflict) {
				return // refused: nothing to render
			}
			must(t, err)
			tbl, err := s.DashboardTable(ctx)
			must(t, err)
			f := memberFile(tbl)
			if _, err := f.Marshal(); err != nil {
				t.Fatalf("the store accepted a key set the file refuses: %v", err)
			}
			for _, k := range f.Issuer.Keys {
				if _, err := jwtx.DashboardKeyFromJWK(k.Kid, k.N, k.E); err != nil {
					t.Fatalf("the store accepted a key set the gateway refuses (key %q): %v", k.Kid, err)
				}
			}
		})
	}
}

// Two revocations racing for the last place, and two adds racing for the
// node's last member row, each give exactly one success over many rounds.
func TestCaps_LastPlaceRaces(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	sqlExec(t, s, `insert into principal_revocation (issuer, subject, not_before)
		select 'i', 'fill' || g, now() from generate_series(1, $1) g`, dashfile.MaxRevocations-1)
	for round := range 10 {
		errs := race(2, func(i int) error { return s.Revoke(ctx, "i", fmt.Sprint("new", round, "-", i), memberDBNow(t, s)) })
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, ErrConflict):
				t.Fatal(err)
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d revocations took the last place", round, won)
		}
		if n := count(t, s, "select count(*) from principal_revocation"); n != dashfile.MaxRevocations {
			t.Fatalf("round %d: %d revocations", round, n)
		}
		sqlExec(t, s, "delete from principal_revocation where subject like 'new%'")
	}
}

// A project in a state the file does not carry keeps its member rows; they
// count against the node, and come back into the file only through a live
// state: the node-wide count must cover every state from which the project
// can return to the file.
func TestAddMember_NodeCountCoversEveryReturnableState(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	full := dashfile.MaxMemberRows / dashfile.MaxMembers
	for i := range full {
		memberFill(t, s, newActive(t, s, i+1), dashfile.MaxMembers)
	}
	sqlExec(t, s, "update project set state = 'deleting' where ref = $1", ref(1))
	err := s.AddMember(ctx, Member{Ref: newActive(t, s, 200), Issuer: "i", Subject: "s", Role: "owner"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("rows of a deleting project were not counted: %v", err)
	}
}
