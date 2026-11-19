package dashfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

const ref1, ref2 = "abcdefghij0123456789", "bcdefghij0123456789a"

const good = `{"generation":7,"node":"local","studio_domain":"studio.test","studio":"http://10.212.0.3:3000",` +
	`"issuer":{"iss":"https://issuer.test","client_id":"supapace","authorize_url":"https://issuer.test/authorize",` +
	`"end_session_url":"","session_seconds":28800,"keys":[{"kid":"k1","kty":"RSA","n":"AQAB","e":"AQAB"}]},` +
	`"revoked":[{"iss":"https://issuer.test","sub":"user-9","not_before":1800000000}],` +
	`"projects":{"` + ref1 + `":{"name":"Shop","members":[{"iss":"https://issuer.test","sub":"user-1","role":"owner"},` +
	`{"iss":"https://issuer.test","sub":"user-2","role":"read_only"}]},"` + ref2 + `":{"name":"","members":[]}}}`

func TestDashfile_RoundTrip(t *testing.T) {
	f, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	want := File{
		Generation: 7, Node: "local", StudioDomain: "studio.test", Studio: "http://10.212.0.3:3000",
		Issuer: &Issuer{Iss: "https://issuer.test", ClientID: "supapace", AuthorizeURL: "https://issuer.test/authorize",
			SessionSeconds: 28800, Keys: []IssuerKey{{Kid: "k1", Kty: "RSA", N: "AQAB", E: "AQAB"}}},
		Revoked: []Revocation{{Iss: "https://issuer.test", Sub: "user-9", NotBefore: 1800000000}},
		Projects: map[string]Project{
			ref1: {Name: "Shop", Members: []Member{{"https://issuer.test", "user-1", dashcfg.RoleOwner}, {"https://issuer.test", "user-2", dashcfg.RoleReadOnly}}},
			ref2: {Name: "", Members: []Member{}},
		},
	}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("Parse =\n%+v\nwant\n%+v", f, want)
	}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != good {
		t.Fatalf("Marshal =\n%s\nwant\n%s", b, good)
	}
	// Empty collections marshal as empty, never null, and parse back.
	e := File{Generation: 1, Node: "local", StudioDomain: "studio.test", Studio: "http://10.212.0.3:3000"}
	b, err = e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"generation":1,"node":"local","studio_domain":"studio.test","studio":"http://10.212.0.3:3000","issuer":null,"revoked":[],"projects":{}}` {
		t.Fatal(string(b))
	}
	if _, err := Parse(b); err != nil {
		t.Fatal(err)
	}
	// Nil members and keys marshal as [] too.
	e.Issuer = &Issuer{Iss: "i", ClientID: "c", AuthorizeURL: "a", SessionSeconds: 1}
	e.Projects = map[string]Project{ref1: {Name: "x"}}
	b, err = e.Marshal()
	if err != nil || !strings.Contains(string(b), `"keys":[]`) || !strings.Contains(string(b), `"members":[]`) {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatal(err)
	}
	// Marshal validates.
	e.Generation = 0
	if _, err := e.Marshal(); err == nil {
		t.Fatal("Marshal wrote generation 0")
	}
}

func TestDashfile_NullIssuer(t *testing.T) {
	s := strings.Replace(good, good[strings.Index(good, `"issuer":{`):strings.Index(good, `,"revoked"`)], `"issuer":null`, 1)
	f, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	if f.Issuer != nil {
		t.Fatal("issuer not nil")
	}
	b, _ := f.Marshal()
	if string(b) != s {
		t.Fatalf("%s\n%s", b, s)
	}
	// Absent is not null.
	s = strings.Replace(s, `"issuer":null,`, ``, 1)
	if _, err := Parse([]byte(s)); err == nil {
		t.Fatal("an absent issuer was accepted")
	}
}

func repeat(n int, f func(i int) string) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(f(i))
	}
	return b.String()
}

func refN(i int) string { return fmt.Sprintf("r%019d", i) }

func TestDashfile_Strict(t *testing.T) {
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatal(err) // the control every case mutates
	}
	sub := func(old, new string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	head := `{"generation":7,"node":"local","studio_domain":"studio.test","studio":"http://10.212.0.3:3000","issuer":null,`
	member := func(i int) string { return fmt.Sprintf(`{"iss":"i","sub":"s%d","role":"owner"}`, i) }
	project := func(i int) string { return `"` + refN(i) + `":{"name":"","members":[]}` }
	revocation := func(int) string { return `{"iss":"i","sub":"s","not_before":1}` }
	key := func(i int) string { return fmt.Sprintf(`{"kid":"k%d","kty":"RSA","n":"AQAB","e":"AQAB"}`, i) }
	withKeys := func(n int) string {
		return sub(`"keys":[{"kid":"k1","kty":"RSA","n":"AQAB","e":"AQAB"}]`, `"keys":[`+repeat(n, key)+`]`)
	}
	cases := map[string]string{
		"unknown top member":      sub(`"generation":7,`, `"generation":7,"extra":1,`),
		"unknown issuer member":   sub(`"client_id"`, `"x":1,"client_id"`),
		"unknown project member":  sub(`{"name":"Shop",`, `{"name":"Shop","x":1,`),
		"unknown member member":   sub(`"role":"owner"}`, `"role":"owner","x":1}`),
		"unknown revocation":      sub(`"not_before":1800000000}`, `"not_before":1800000000,"x":1}`),
		"key with class":          sub(`"e":"AQAB"}`, `"e":"AQAB","class":"dashboard"}`),
		"case-variant member":     sub(`"generation":7`, `"Generation":7`),
		"folded member":           sub(`"iss":"https://issuer.test","client_id"`, `"ſiss":"https://issuer.test","client_id"`),
		"duplicate member":        sub(`"generation":7,`, `"generation":7,"generation":8,`),
		"duplicate issuer member": sub(`"client_id":"supapace",`, `"client_id":"supapace","client_id":"x",`),
		"duplicate project key":   sub(`,"`+ref2+`":`, `,"`+ref1+`":{"name":"","members":[]},"`+ref2+`":`),
		"missing member":          sub(`"node":"local",`, ``),
		"missing key member":      sub(`"kid":"k1",`, ``),
		"trailing data":           good + ` {}`,
		"trailing garbage":        good + `x`,
		"not an object":           `[]`,
		"empty":                   ``,
		"null file":               `null`,
		"null revoked":            sub(`"revoked":[{"iss":"https://issuer.test","sub":"user-9","not_before":1800000000}]`, `"revoked":null`),
		"null projects":           strings.Replace(good, good[strings.Index(good, `"projects":`):], `"projects":null}`, 1),
		"null members":            sub(`"members":[]`, `"members":null`),
		"null keys":               sub(`"keys":[{"kid":"k1","kty":"RSA","n":"AQAB","e":"AQAB"}]`, `"keys":null`),
		"string generation":       sub(`"generation":7`, `"generation":"7"`),
		"fractional generation":   sub(`"generation":7`, `"generation":7.5`),
		"exponent generation":     sub(`"generation":7`, `"generation":7e0`),
		"generation 0":            sub(`"generation":7`, `"generation":0`),
		"negative not_before":     sub(`"not_before":1800000000`, `"not_before":-1`),
		"empty node":              sub(`"node":"local"`, `"node":""`),
		"duplicate principal":     sub(`"sub":"user-2","role":"read_only"`, `"sub":"user-1","role":"read_only"`),
		"bad role":                sub(`"role":"read_only"`, `"role":"admin"`),
		"upper-case role":         sub(`"role":"owner"`, `"role":"Owner"`),
		"bad ref":                 sub(`"`+ref2+`"`, `"ABCDEFGHIJ0123456789"`),
		"short ref":               sub(`"`+ref2+`"`, `"bcdefghij0123456789"`),
		"bad domain":              sub(`"studio_domain":"studio.test"`, `"studio_domain":"Studio.test"`),
		"single-label domain":     sub(`"studio_domain":"studio.test"`, `"studio_domain":"studio"`),
		"studio https":            sub(`"http://10.212.0.3:3000"`, `"https://10.212.0.3:3000"`),
		"studio port":             sub(`"http://10.212.0.3:3000"`, `"http://10.212.0.3:3001"`),
		"studio host name":        sub(`"http://10.212.0.3:3000"`, `"http://studio.test:3000"`),
		"studio non-canonical":    sub(`"http://10.212.0.3:3000"`, `"http://10.212.0.03:3000"`),
		"studio path":             sub(`"http://10.212.0.3:3000"`, `"http://10.212.0.3:3000/"`),
		"studio IPv6":             sub(`"http://10.212.0.3:3000"`, `"http://[::1]:3000"`),
		"studio 4in6":             sub(`"http://10.212.0.3:3000"`, `"http://::ffff:10.212.0.3:3000"`),
		"empty member sub":        sub(`"sub":"user-1"`, `"sub":""`),
		"control char in sub":     sub(`"sub":"user-1"`, `"sub":"user\u00011"`),
		"long sub":                sub(`"sub":"user-1"`, `"sub":"`+strings.Repeat("s", 256)+`"`),
		"empty issuer iss":        sub(`"iss":"https://issuer.test","client_id"`, `"iss":"","client_id"`),
		"empty client id":         sub(`"client_id":"supapace"`, `"client_id":""`),
		"empty authorize url":     sub(`"authorize_url":"https://issuer.test/authorize"`, `"authorize_url":""`),
		"session 0":               sub(`"session_seconds":28800`, `"session_seconds":0`),
		"session above 8 h":       sub(`"session_seconds":28800`, `"session_seconds":28801`),
		"key not RSA":             sub(`"kty":"RSA"`, `"kty":"EC"`),
		"key empty kid":           sub(`"kid":"k1"`, `"kid":""`),
		"key empty n":             sub(`"n":"AQAB"`, `"n":""`),
		"object for array":        sub(`"members":[]`, `"members":{}`),
		"object for string":       sub(`"node":"local"`, `"node":{}`),
		"number for string":       sub(`"node":"local"`, `"node":1`),
		"too many keys":           withKeys(MaxKeys + 1),
		"too many members":        head + `"revoked":[],"projects":{"` + ref1 + `":{"name":"","members":[` + repeat(MaxMembers+1, member) + `]}}}`,
		"too many projects":       head + `"revoked":[],"projects":{` + repeat(MaxProjects+1, project) + `}}`,
		"too many revocations":    head + `"revoked":[` + repeat(MaxRevocations+1, revocation) + `],"projects":{}}`,
		"deep nesting":            head + `"revoked":[` + strings.Repeat(`[`, 10000) + strings.Repeat(`]`, 10000) + `],"projects":{}}`,
		"unterminated":            good[:len(good)-1],
		"invalid utf-8 in a name": sub(`"name":"Shop"`, "\"name\":\"Sh\xffp\""),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(s)); err == nil {
				t.Fatalf("accepted: %.300s", s)
			}
		})
	}
	// Controls at each cap: exactly the cap is read.
	for name, s := range map[string]string{
		"keys at cap":        withKeys(MaxKeys),
		"members at cap":     head + `"revoked":[],"projects":{"` + ref1 + `":{"name":"","members":[` + repeat(MaxMembers, member) + `]}}}`,
		"projects at cap":    head + `"revoked":[],"projects":{` + repeat(MaxProjects, project) + `}}`,
		"revocations at cap": head + `"revoked":[` + repeat(MaxRevocations, revocation) + `],"projects":{}}`,
		"same principal in two projects": head + `"revoked":[],"projects":{"` + ref1 + `":{"name":"","members":[` + member(0) +
			`]},"` + ref2 + `":{"name":"","members":[` + member(0) + `]}}}`,
		"white space between tokens": strings.ReplaceAll(good, `,"`, ",\n \""),
	} {
		if _, err := Parse([]byte(s)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The caps, the ref shape and the value kinds are refused by the first pass, before any value
	// is built.
	for _, name := range []string{"too many keys", "too many members", "too many projects", "too many revocations", "bad ref",
		"object for array", "object for string", "number for string", "string generation", "null members"} {
		dec := json.NewDecoder(strings.NewReader(cases[name]))
		dec.UseNumber()
		if err := walk(dec, fileShape); err == nil {
			t.Errorf("%s: the first pass accepted it", name)
		}
	}
	// Marshal refuses what Parse refuses: each cap, a bad ref, a duplicate principal.
	big := File{Generation: 1, Node: "local", StudioDomain: "studio.test", Studio: "http://10.212.0.3:3000",
		Revoked: make([]Revocation, MaxRevocations+1), Projects: map[string]Project{}}
	for i := range big.Revoked {
		big.Revoked[i] = Revocation{Iss: "i", Sub: "s", NotBefore: 1}
	}
	if _, err := big.Marshal(); err == nil {
		t.Error("Marshal wrote too many revocations")
	}
	big.Revoked = nil
	for i := range MaxProjects + 1 {
		big.Projects[refN(i)] = Project{}
	}
	if _, err := big.Marshal(); err == nil {
		t.Error("Marshal wrote too many projects")
	}
	big.Projects = map[string]Project{ref1: {Members: make([]Member, MaxMembers+1)}}
	for i := range big.Projects[ref1].Members {
		big.Projects[ref1].Members[i] = Member{Iss: "i", Sub: strconv.Itoa(i), Role: dashcfg.RoleOwner}
	}
	if _, err := big.Marshal(); err == nil {
		t.Error("Marshal wrote too many members")
	}
	big.Projects = map[string]Project{"ABCDEFGHIJ0123456789": {}}
	if _, err := big.Marshal(); err == nil {
		t.Error("Marshal wrote a bad ref")
	}
	big.Projects = nil
	if _, err := big.Marshal(); err != nil {
		t.Errorf("control: %v", err)
	}
	f, _ := Parse([]byte(good))
	f.Issuer.Keys = make([]IssuerKey, MaxKeys+1)
	for i := range f.Issuer.Keys {
		f.Issuer.Keys[i] = IssuerKey{Kid: strconv.Itoa(i), Kty: "RSA", N: "AQAB", E: "AQAB"}
	}
	if _, err := f.Marshal(); err == nil {
		t.Error("Marshal wrote 17 keys")
	}
	f, _ = Parse([]byte(good))
	p := f.Projects[ref1]
	p.Members = append(p.Members, p.Members[0])
	f.Projects[ref1] = p
	if _, err := f.Marshal(); err == nil {
		t.Error("Marshal wrote a duplicate principal")
	}
}

// The file's caps and the slice count dashcfg.For admits agree, so the file can
// always carry every live project.
func TestDashfile_CapsMatchTheNode(t *testing.T) {
	c := nodecfg.Config{
		ProjectBlock: "10.214.0.0/15", SlicePrefix: 27, PlatformSubnet: "10.212.0.0/16",
		PlatformIPRange: "10.212.128.0/23", GatewayIP: "10.212.0.2", UIDBase: 700000, UIDCount: 65536,
	}
	if c.Slices() != MaxProjects {
		t.Fatal(c.Slices())
	}
	if _, err := dashcfg.For(c); err != nil {
		t.Fatalf("a node of MaxProjects slices: %v", err)
	}
	c.SlicePrefix++
	if _, err := dashcfg.For(c); err == nil {
		t.Fatal("a node of more slices than the file carries was accepted")
	}
}

// The file's package takes nothing of the token code: keys are converted by
// the gateway when it loads the table.
func TestDashfile_ImportsNoTokenCode(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if strings.HasSuffix(p, "/jwtx") || strings.HasSuffix(p, "/dashtok") || p == "os" || p == "net" || p == "time" {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(good))
	f.Add([]byte(`{"generation":1,"node":"local","studio_domain":"studio.test","studio":"http://10.212.0.3:3000","issuer":null,"revoked":[],"projects":{}}`))
	f.Add([]byte(`{"generation":1,"generation":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Parse(b)
		if err != nil {
			return
		}
		out, err := v.Marshal()
		if err != nil {
			t.Fatalf("parsed but does not marshal: %v", err)
		}
		v2, err := Parse(out)
		if err != nil || !reflect.DeepEqual(v, v2) {
			t.Fatalf("round trip: %v", err)
		}
		if out2, _ := v2.Marshal(); !bytes.Equal(out, out2) {
			t.Fatal("marshal is not canonical")
		}
	})
}

// encMax is the most bytes the encoder writes for one byte of a string: "<",
// ">", "&", a control character and a byte of invalid UTF-8 become six.
const encMax = 6

// worstString is a quoted string of n bytes at encMax bytes each.
func worstString(n int) int { return 2 + encMax*n }

// marshalLen is the length of v as Marshal's encoder writes it.
func marshalLen(t *testing.T, v any) int {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// The largest file the caps allow, computed from the constants with every
// string at its cap and every byte of it at six, fits MaxBytes.
func TestCaps_WorstCaseFromTheConstantsFitsMaxBytes(t *testing.T) {
	// The encoder's own figure: no byte of a string takes more than encMax.
	for c := range 256 {
		if n := marshalLen(t, string([]byte{byte(c)})) - 2; n > encMax {
			t.Fatalf("byte %#x encodes as %d bytes", c, n)
		}
	}
	if n := marshalLen(t, strings.Repeat("<", 255)); n != worstString(255) {
		t.Fatalf("255 × '<' encodes as %d bytes, want %d", n, worstString(255))
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	// Each row with empty strings, the widest number, and its separating comma;
	// then the strings at their caps.
	member := marshalLen(t, Member{Role: dashcfg.RoleReadOnly}) + 1 - 2*2 + 2*worstString(255)
	revocation := marshalLen(t, Revocation{NotBefore: maxInt64}) + 1 - 2*2 + 2*worstString(255)
	project := len(`"`+ref1+`":`) + marshalLen(t, Project{Members: []Member{}}) + 1 - 2 + worstString(MaxNameBytes)
	key := marshalLen(t, IssuerKey{}) + 1 - 4*2 + worstString(MaxKidBytes) + worstString(3) + worstString(MaxNBytes) + worstString(MaxEBytes)
	head := marshalLen(t, File{Generation: maxInt64, Issuer: &Issuer{SessionSeconds: maxInt64, Keys: []IssuerKey{}},
		Revoked: []Revocation{}, Projects: map[string]Project{}}) -
		7*2 + worstString(MaxNodeBytes) + worstString(253) + worstString(len("http://255.255.255.255:3000")) +
		worstString(255) + worstString(MaxClientIDBytes) + 2*worstString(MaxURLBytes)
	// The arithmetic the caps were chosen by: a member row of 3,099 bytes and a
	// revocation of 3,113.
	if member != 3099 || revocation != 3113 {
		t.Fatalf("member row %d, revocation row %d; want 3099 and 3113", member, revocation)
	}
	total := head + MaxKeys*key + MaxMemberRows*member + MaxRevocations*revocation + MaxProjects*project
	t.Logf("worst case %d bytes (%.1f MB) of %d", total, float64(total)/1e6, MaxBytes)
	if total > MaxBytes {
		t.Fatalf("the caps allow a file of %d bytes, above MaxBytes %d", total, MaxBytes)
	}
	// Every cap is part of the sum: 16,384 member rows and 4,096 revocations
	// (63.5 MB), 4,096 projects of 432 bytes (1.8 MB), the head and sixteen keys
	// (0.2 MB). A cap changed without the bound being checked again fails here.
	if want := 16384*3099 + 4096*3113 + 4096*432 + 192_319; total != want {
		t.Fatalf("worst case %d bytes, want %d", total, want)
	}
}

// pad makes b a document of exactly n bytes; trailing white space is valid.
func pad(b []byte, n int) []byte { return append(b, bytes.Repeat([]byte(" "), n-len(b))...) }

func TestParse_AboveMaxBytes_Refused(t *testing.T) {
	if _, err := Parse(pad([]byte(good), MaxBytes)); err != nil {
		t.Fatalf("a file of exactly MaxBytes: %v", err)
	}
	if _, err := Parse(pad([]byte(good), MaxBytes+1)); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("a file of MaxBytes+1 bytes: %v", err)
	}
}

func TestMarshal_AboveMaxBytes_Refused(t *testing.T) {
	f, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.marshal(len(good))
	if err != nil || string(b) != good {
		t.Fatalf("output of exactly the bound: %v", err)
	}
	if _, err := f.marshal(len(good) - 1); err == nil {
		t.Fatal("output one byte above the bound was returned")
	}
}

// Each string one byte above its cap is refused by Parse and Marshal; at the
// cap it is accepted. So are the whole file's member rows and revocations.
func TestValidate_StringCaps(t *testing.T) {
	type edit func(f *File, n int)
	at := func(c byte, n int) string { return strings.Repeat(string(c), n) }
	for name, c := range map[string]struct {
		cap int
		set edit
	}{
		"node":            {MaxNodeBytes, func(f *File, n int) { f.Node = at('n', n) }},
		"iss":             {255, func(f *File, n int) { f.Issuer.Iss = at('<', n) }},
		"client_id":       {MaxClientIDBytes, func(f *File, n int) { f.Issuer.ClientID = at('c', n) }},
		"authorize_url":   {MaxURLBytes, func(f *File, n int) { f.Issuer.AuthorizeURL = at('a', n) }},
		"end_session_url": {MaxURLBytes, func(f *File, n int) { f.Issuer.EndSessionURL = at('e', n) }},
		"kid":             {MaxKidBytes, func(f *File, n int) { f.Issuer.Keys[0].Kid = at('k', n) }},
		"n":               {MaxNBytes, func(f *File, n int) { f.Issuer.Keys[0].N = at('A', n) }},
		"e":               {MaxEBytes, func(f *File, n int) { f.Issuer.Keys[0].E = at('A', n) }},
		"revocation sub":  {255, func(f *File, n int) { f.Revoked[0].Sub = at('s', n) }},
		"member iss":      {255, func(f *File, n int) { f.Projects[ref1].Members[0].Iss = at('i', n) }},
		"name":            {MaxNameBytes, func(f *File, n int) { p := f.Projects[ref1]; p.Name = at('<', n); f.Projects[ref1] = p }},
	} {
		t.Run(name, func(t *testing.T) {
			for _, n := range []int{c.cap, c.cap + 1} {
				f, err := Parse([]byte(good))
				if err != nil {
					t.Fatal(err)
				}
				c.set(&f, n)
				b, merr := f.Marshal()
				if n == c.cap {
					if merr != nil {
						t.Fatalf("at the cap: %v", merr)
					}
					if _, err := Parse(b); err != nil {
						t.Fatalf("at the cap, Parse: %v", err)
					}
					continue
				}
				if merr == nil {
					t.Fatal("Marshal wrote a string above its cap")
				}
				f.Generation = 7
				raw, _ := json.Marshal(f) // the same file, written without the check
				if _, err := Parse(raw); err == nil {
					t.Fatal("Parse read a string above its cap")
				}
			}
		})
	}
	// MaxMemberRows over the whole file: 64 projects of 256 rows, then one more.
	f := File{Generation: 1, Node: "local", StudioDomain: "studio.test", Studio: "http://10.212.0.3:3000", Projects: map[string]Project{}}
	for p := range MaxMemberRows / MaxMembers {
		ms := make([]Member, MaxMembers)
		for i := range ms {
			ms[i] = Member{Iss: "i", Sub: strconv.Itoa(i), Role: dashcfg.RoleOwner}
		}
		f.Projects[refN(p)] = Project{Members: ms}
	}
	b, err := f.Marshal()
	if err != nil {
		t.Fatalf("%d member rows: %v", MaxMemberRows, err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatalf("%d member rows, Parse: %v", MaxMemberRows, err)
	}
	f.Projects[refN(MaxMemberRows/MaxMembers)] = Project{Members: []Member{{Iss: "i", Sub: "s", Role: dashcfg.RoleOwner}}}
	if _, err := f.Marshal(); err == nil {
		t.Fatalf("Marshal wrote %d member rows", MaxMemberRows+1)
	}
	raw, _ := json.Marshal(f)
	if _, err := Parse(raw); err == nil {
		t.Fatalf("Parse read %d member rows", MaxMemberRows+1)
	}
	// MaxRevocations: 4,096 is read, 4,097 is not.
	if MaxRevocations != 4096 {
		t.Fatalf("MaxRevocations %d", MaxRevocations)
	}
}
