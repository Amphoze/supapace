package routes

import (
	"strings"
	"testing"
)

func TestParse_RejectsMalformed(t *testing.T) {
	good, _ := sample().Marshal()
	g := string(good)
	// Accepted limit: encoding/json matches keys case-insensitively and keeps the last
	// of duplicate keys; the route file is written only by the agent.
	cases := map[string]string{
		"empty":               "",
		"whitespace":          " \n",
		"array":               "[]",
		"string":              `"x"`,
		"trailing brace":      g + "}",
		"trailing bracket":    g + "]",
		"trailing garbage":    g + "x",
		"two documents":       g + g,
		"null":                "null",
		"empty object":        "{}",
		"generation zero":     strings.Replace(g, `"generation":17`, `"generation":0`, 1),
		"generation negative": strings.Replace(g, `"generation":17`, `"generation":-5`, 1),
		"empty domain":        strings.Replace(g, `"domain":"sp.test"`, `"domain":""`, 1),
		"domain with space":   strings.Replace(g, `"domain":"sp.test"`, `"domain":"SP TEST"`, 1),
		"domain empty label":  strings.Replace(g, `"domain":"sp.test"`, `"domain":"sp..test"`, 1),
		"domain non-ASCII":    strings.Replace(g, `"domain":"sp.test"`, `"domain":"spé.test"`, 1),
		"null project":        `{"generation":1,"domain":"sp.test","projects":{"` + refA + `":null}}`,
		"null key class":      strings.Replace(g, `"class":"issuer"`, `"class":null`, 1),
		"empty kid":           strings.Replace(g, `"kid":"k3"`, `"kid":""`, 1),
		"kty EC":              strings.Replace(g, `"kty":"RSA"`, `"kty":"EC"`, 1),
		"generation string":   strings.Replace(g, `"generation":17`, `"generation":"17"`, 1),
		"generation float":    strings.Replace(g, `"generation":17`, `"generation":1.5`, 1),
		"generation overflow": strings.Replace(g, `"generation":17`, `"generation":99999999999999999999`, 1),
		"ref trailing nl":     strings.Replace(g, refA, refA+`\n`, 1),
		"ref 21 chars":        strings.Replace(g, refA, refA+"a", 1),
		"ref uppercase":       strings.Replace(g, refA, strings.ToUpper(refA), 1),
		"ref underscore":      strings.Replace(g, refA, refA[:19]+"_", 1),
		"ref unicode":         strings.Replace(g, refA, refA[:19]+"é", 1),
		"rest leading zeros":  strings.Replace(g, "10.212.0.30", "010.212.000.030", 1),
		"rest octet 256":      strings.Replace(g, "10.212.0.30", "10.212.0.256", 1),
		"rest v4-in-v6":       strings.Replace(g, "10.212.0.30", "[:"+":ffff:10.212.0.30]", 1),
		"rest zone":           strings.Replace(g, "10.212.0.30", "10.212.0.30%eth0", 1),
		"rest trailing slash": strings.Replace(g, ":3000", ":3000/", 1),
		"rest userinfo":       strings.Replace(g, "http://", "http://u@", 1),
		"rest empty":          strings.Replace(g, "http://10.212.0.30:3000", "", 1),
		"rest nl":             strings.Replace(g, ":3000", ":3000\\n", 1),
		"rest uppercase":      strings.Replace(g, "http://", "HTTP://", 1),
		"rest port 03000":     strings.Replace(g, ":3000", ":03000", 1),
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A file cut at any byte must never be accepted (partial write).
func TestParse_EveryPrefixRejected(t *testing.T) {
	good, _ := sample().Marshal()
	for n := 0; n < len(good); n++ {
		if _, err := Parse(good[:n]); err == nil {
			t.Fatalf("prefix of %d/%d bytes accepted: %q", n, len(good), good[:n])
		}
	}
	if _, err := Parse(good); err != nil {
		t.Fatal(err)
	}
}

func TestMarshal_RefusesWhatParseRefuses(t *testing.T) {
	bad := []func(*File){
		func(f *File) { f.Generation = 0 },
		func(f *File) { f.Domain = "" },
		func(f *File) { p := f.Projects[refA]; p.Rest = "http://[::1]:3000"; f.Projects[refA] = p },
		func(f *File) { p := f.Projects[refA]; p.State = ""; f.Projects[refA] = p },
		func(f *File) { f.Projects["BAD"] = f.Projects[refA] },
		func(f *File) { p := f.Projects[refA]; p.Keys = p.Keys[1:]; f.Projects[refA] = p },
		func(f *File) { p := f.Projects[refA]; p.Keys[0].Kty = "oct"; f.Projects[refA] = p },
	}
	for i, m := range bad {
		f := sample()
		m(&f)
		if _, err := f.Marshal(); err == nil {
			t.Errorf("case %d: Marshal accepted", i)
		}
	}
}

func TestParse_RoundTripVariants(t *testing.T) {
	for name, f := range map[string]File{
		"nil projects":   {Generation: 1, Domain: "sp.test"},
		"empty projects": {Generation: 1, Domain: "sp.test", Projects: map[string]Project{}},
		"max gen":        {Generation: 1<<63 - 1, Domain: "sp.test"},
		"nil roles":      func() File { f := sample(); p := f.Projects[refA]; p.UserRoles = nil; f.Projects[refA] = p; return f }(),
		"empty roles": func() File {
			f := sample()
			p := f.Projects[refA]
			p.UserRoles = []string{}
			f.Projects[refA] = p
			return f
		}(),
		"draining": func() File {
			f := sample()
			p := f.Projects[refA]
			p.State = "draining"
			f.Projects[refA] = p
			return f
		}(),
	} {
		b, err := f.Marshal()
		if err != nil {
			t.Errorf("%s: marshal: %v", name, err)
			continue
		}
		got, err := Parse(b)
		if err != nil {
			t.Errorf("%s: parse: %v", name, err)
			continue
		}
		b2, _ := got.Marshal()
		if string(b) != string(b2) {
			t.Errorf("%s: second marshal differs", name)
		}
	}
}

func TestParse_ManyProjects(t *testing.T) {
	f := sample()
	base := f.Projects[refA]
	for i := 0; i < 5000; i++ {
		ref := []byte(refA)
		for j, n := 19, i; j >= 0 && n > 0; j, n = j-1, n/10 {
			ref[j] = byte('0' + n%10)
		}
		f.Projects[string(ref)] = base
	}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Parse(b); err != nil || len(got.Projects) != len(f.Projects) {
		t.Fatalf("%v %d", err, len(got.Projects))
	}
	// A large padded file is parsed without trouble.
	if _, err := Parse(append(b, strings.Repeat(" ", 20<<20)...)); err != nil {
		t.Fatal(err)
	}
}
