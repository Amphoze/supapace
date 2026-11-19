package dashsock

import (
	"encoding/json"
	"testing"
)

func TestAnswers_Shape(t *testing.T) {
	rows := 1000
	r := ResolveAnswer{
		Ref: "abcdefghij0123456789", Name: "Shop", State: "active", DBVersion: "17.6.1", PgMeta: 1,
		DSNRW: "postgresql://postgres:x", DSNRO: "postgresql://supabase_read_only_user:y",
		APIURL:     "https://abcdefghij0123456789.sp.test",
		DataAPI:    DataAPI{Schemas: []string{"public", "graphql_public"}, ExtraSearchPath: []string{"public", "extensions"}},
		Generation: 4, At: "2026-11-19T10:00:00Z",
	}
	check := func(v any, want string) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want {
			t.Fatalf("got\n%s\nwant\n%s", b, want)
		}
	}
	check(r, `{"ref":"abcdefghij0123456789","name":"Shop","state":"active","db_version":"17.6.1","pg_meta":1,`+
		`"dsn_rw":"postgresql://postgres:x","dsn_ro":"postgresql://supabase_read_only_user:y",`+
		`"api_url":"https://abcdefghij0123456789.sp.test",`+
		`"data_api":{"schemas":["public","graphql_public"],"extra_search_path":["public","extensions"],"max_rows":null},`+
		`"generation":4,"at":"2026-11-19T10:00:00Z"}`)
	// A read_only member of a project without its read-only secret: both DSNs absent, not empty.
	r.DSNRW, r.DSNRO, r.DataAPI.MaxRows, r.PgMeta = "", "", &rows, 0
	check(r, `{"ref":"abcdefghij0123456789","name":"Shop","state":"active","db_version":"17.6.1","pg_meta":0,`+
		`"api_url":"https://abcdefghij0123456789.sp.test",`+
		`"data_api":{"schemas":["public","graphql_public"],"extra_search_path":["public","extensions"],"max_rows":1000},`+
		`"generation":4,"at":"2026-11-19T10:00:00Z"}`)

	k := KeysAnswer{
		AnonKey:        "a.b.c",
		SigningKeys:    []SigningKey{{Kid: "k1", Class: "project", Alg: "RS256", Kty: "RSA", N: "AQAB", E: "AQAB"}},
		ServiceRoleKey: "d.e.f",
	}
	check(k, `{"anon_key":"a.b.c","signing_keys":[{"kid":"k1","class":"project","alg":"RS256","kty":"RSA","n":"AQAB","e":"AQAB"}],"service_role_key":"d.e.f"}`)
	k.ServiceRoleKey = ""
	check(k, `{"anon_key":"a.b.c","signing_keys":[{"kid":"k1","class":"project","alg":"RS256","kty":"RSA","n":"AQAB","e":"AQAB"}]}`)

	if HeaderAssertion != "X-Supapace-Assertion" {
		t.Fatal(HeaderAssertion)
	}
}

func TestRoleClass(t *testing.T) {
	for role, want := range map[string]string{"owner": "rw", "developer": "rw", "read_only": "ro", "": "", "admin": "", "Owner": ""} {
		if got := RoleClass(role); got != want {
			t.Errorf("RoleClass(%q) = %q, want %q", role, got, want)
		}
	}
}
