package routes

import (
	"reflect"
	"strings"
	"testing"
)

const refA = "abcdefghij0123456789"

func sample() File {
	return File{
		Generation: 17,
		Domain:     "sp.test",
		Projects: map[string]Project{refA: {
			State:     "active",
			Rest:      "http://10.212.0.30:3000",
			UserRoles: []string{"authenticated"},
			Keys: []Key{
				{KID: "k1", Class: "anon", Kty: "RSA", N: "nnn", E: "AQAB"},
				{KID: "k2", Class: "service_role", Kty: "RSA", N: "nnn", E: "AQAB"},
				{KID: "k3", Class: "issuer", Kty: "RSA", N: "nnn", E: "AQAB"},
			},
		}},
	}
}

func TestParse_RoundTrip(t *testing.T) {
	f := sample()
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse(Marshal(f)) = %v\n%s", err, b)
	}
	if !reflect.DeepEqual(got, f) {
		t.Fatalf("round trip changed the file:\n got %+v\nwant %+v", got, f)
	}
	empty, err := Parse([]byte(`{"generation":1,"domain":"sp.test","projects":{}}`))
	if err != nil || len(empty.Projects) != 0 {
		t.Fatalf("empty table: %+v, %v", empty, err)
	}
}

func TestParse_Rejects(t *testing.T) {
	good, err := sample().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unknown top-level field": `"generation":17,` + `"extra":1,`,
		"unknown project field":   `"state":"active",` + `"extra":1,`,
		"unknown key field":       `"class":"anon",` + `"extra":1,`,
		"bad ref":                 refA + `"` + "|" + strings.ToUpper(refA[:3]) + refA[3:] + `"`,
		"short ref":               refA + `"` + "|" + refA[:19] + `"`,
		"bad state":               `"state":"active"` + "|" + `"state":"paused"`,
		"https rest":              `"http://10.212.0.30:3000"` + "|" + `"https://10.212.0.30:3000"`,
		"other port":              `"http://10.212.0.30:3000"` + "|" + `"http://10.212.0.30:3001"`,
		"name rest":               `"http://10.212.0.30:3000"` + "|" + `"http://postgrest:3000"`,
		"ipv6 rest":               `"http://10.212.0.30:3000"` + "|" + `"http://[::1]:3000"`,
		"path rest":               `"http://10.212.0.30:3000"` + "|" + `"http://10.212.0.30:3000/x"`,
		"no anon key":             `"class":"anon"` + "|" + `"class":"issuer"`,
		"no service key":          `"class":"service_role"` + "|" + `"class":"issuer"`,
		"bad class":               `"class":"issuer"` + "|" + `"class":"root"`,
		"trailing data":           `}}}` + "|" + `}}}{}`,
	}
	for name, edit := range cases {
		var mutated string
		if old, repl, ok := strings.Cut(edit, "|"); ok {
			if !strings.Contains(string(good), old) {
				t.Fatalf("%s: %q not in sample", name, old)
			}
			mutated = strings.Replace(string(good), old, repl, 1)
		} else { // insert an extra field after the anchor
			anchor := edit[:strings.Index(edit, `"extra"`)]
			if !strings.Contains(string(good), anchor) {
				t.Fatalf("%s: %q not in sample", name, anchor)
			}
			mutated = strings.Replace(string(good), anchor, edit, 1)
		}
		if _, err := Parse([]byte(mutated)); err == nil {
			t.Errorf("%s: Parse accepted\n%s", name, mutated)
		}
	}
	bad := sample()
	bad.Projects[refA] = Project{State: "draining", Rest: "http://10.212.0.30:3000"}
	if _, err := bad.Marshal(); err == nil {
		t.Error("Marshal accepted a project without anon and service keys")
	}
}
