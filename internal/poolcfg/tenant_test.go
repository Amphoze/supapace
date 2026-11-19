package poolcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

const testPassword = `pw-manager-0123456789"\`

func testTenant() Tenant {
	return Tenant{DBHost: ip("10.212.0.6"), DBPort: 24110, PoolSize: 5, MaxClients: 100,
		AllowList:       []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.51.100.7/32")},
		ManagerPassword: testPassword}
}

func TestTenantBody_Exact(t *testing.T) {
	b, err := testTenant().Body()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"tenant":{"db_host":"10.212.0.6","db_port":24110,"db_database":"postgres","ip_version":"v4",` +
		`"require_user":false,"enforce_ssl":true,"auth_query":"SELECT * FROM supapace_pooler.get_auth($1)",` +
		`"default_pool_size":5,"default_max_clients":100,"allow_list":["203.0.113.0/24","198.51.100.7/32"],` +
		`"feature_flags":{"named_prepared_statements":true},` +
		`"users":[{"db_user":"supapace_pooler","db_password":"pw-manager-0123456789\"\\","pool_size":5,` +
		`"mode_type":"transaction","is_manager":true}]}}`
	if string(b) != want {
		t.Fatalf("Body =\n%s\nwant\n%s", b, want)
	}
	if bytes.Contains(b, []byte("sni_hostname")) {
		t.Error("the document names sni_hostname")
	}
	var doc struct {
		Tenant struct {
			Users []struct {
				DBUser     string `json:"db_user"`
				DBPassword string `json:"db_password"`
			} `json:"users"`
		} `json:"tenant"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Tenant.Users) != 1 || doc.Tenant.Users[0].DBUser != ManagerRole || doc.Tenant.Users[0].DBPassword != testPassword {
		t.Errorf("users: %+v", doc.Tenant.Users)
	}
	// The open list.
	open := testTenant()
	open.AllowList = OpenAllowList()
	if b, err := open.Body(); err != nil || !bytes.Contains(b, []byte(`"allow_list":["0.0.0.0/0"]`)) {
		t.Errorf("open list: %s %v", b, err)
	}
}

func TestTenantBody_Refusals(t *testing.T) {
	cases := map[string]func(*Tenant){
		"no host":             func(x *Tenant) { x.DBHost = netip.Addr{} },
		"IPv6 host":           func(x *Tenant) { x.DBHost = ip("2001:db8::1") },
		"unspecified host":    func(x *Tenant) { x.DBHost = ip("0.0.0.0") },
		"broadcast host":      func(x *Tenant) { x.DBHost = ip("255.255.255.255") },
		"multicast host":      func(x *Tenant) { x.DBHost = ip("224.0.0.251") },
		"port 0":              func(x *Tenant) { x.DBPort = 0 },
		"port 65536":          func(x *Tenant) { x.DBPort = 65536 },
		"pool size 0":         func(x *Tenant) { x.PoolSize = 0 },
		"no clients":          func(x *Tenant) { x.MaxClients = 0 },
		"empty allow list":    func(x *Tenant) { x.AllowList = nil },
		"IPv6 prefix":         func(x *Tenant) { x.AllowList = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")} },
		"host bits set":       func(x *Tenant) { x.AllowList = []netip.Prefix{netip.MustParsePrefix("203.0.113.1/24")} },
		"33 prefixes":         func(x *Tenant) { x.AllowList = make([]netip.Prefix, 33); fill(x.AllowList) },
		"no manager password": func(x *Tenant) { x.ManagerPassword = "" },
	}
	for name, mod := range cases {
		x := testTenant()
		mod(&x)
		b, err := x.Body()
		if err == nil || b != nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "pw-manager") {
			t.Errorf("%s: the error carries the password: %v", name, err)
		}
	}
	// Control: 32 prefixes are accepted.
	x := testTenant()
	x.AllowList = make([]netip.Prefix, 32)
	fill(x.AllowList)
	if _, err := x.Body(); err != nil {
		t.Errorf("32 prefixes: %v", err)
	}
}

// fill sets 192.0.2.i/32 in each element.
func fill(p []netip.Prefix) {
	for i := range p {
		p[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 32)
	}
}

func TestTenant_FormattingRedactsThePassword(t *testing.T) {
	x := testTenant()
	x.ManagerPassword = "pw-manager-0123456789"
	type exported struct{ T Tenant }
	type pointer struct{ T *Tenant }
	leaks := func(s string) bool {
		return strings.Contains(s, "pw-manager") || strings.Contains(s, fmt.Sprintf("%x", "pw-manager")) ||
			strings.Contains(s, fmt.Sprintf("%X", "pw-manager"))
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%b", "%o", "%O", "%c", "%U", "%e", "%f", "%g", "%p", "%10.3v", "%-+#v"}
	for _, v := range []struct {
		name string
		v    any
	}{{"value", x}, {"pointer", &x}, {"slice", []Tenant{x}}, {"map", map[string]Tenant{"a": x}},
		{"exported field", exported{x}}, {"pointer field", pointer{&x}}} {
		for _, verb := range verbs {
			// fmt prints %p of a struct value by reflection before any method
			// is asked; go vet refuses that verb on a non-pointer argument.
			if _, isStruct := v.v.(Tenant); verb == "%p" && (isStruct || v.name == "exported field") {
				continue
			}
			if s := fmt.Sprintf(verb, v.v); leaks(s) {
				t.Errorf("%s %s: %s", v.name, verb, s)
			}
		}
		if s := fmt.Sprint(v.v) + fmt.Sprintln(v.v); leaks(s) {
			t.Errorf("%s Sprint: %s", v.name, s)
		}
		if b, _ := json.Marshal(v.v); leaks(string(b)) {
			t.Errorf("%s json: %s", v.name, b)
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v.v)
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "v", v.v)
		if leaks(buf.String()) {
			t.Errorf("%s slog: %s", v.name, buf.String())
		}
	}
	// Control: the formatted value still says what it is, and the document,
	// the one place the password belongs, carries it.
	if s := fmt.Sprint(x); !strings.Contains(s, "10.212.0.6") || !strings.Contains(s, "24110") {
		t.Errorf("String = %s", s)
	}
	if b, _ := x.Body(); !leaks(string(b)) {
		t.Error("the control: Body lacks the password")
	}
}

func TestValidAllowList_RefusesNodeInternalAndIPv6(t *testing.T) {
	c := defaultCfg()
	for _, s := range []string{
		"2001:db8::/32", "::ffff:203.0.113.0/120", // IPv6
		"10.213.5.0/24",                                                   // the project block
		"10.212.0.0/24",                                                   // the platform subnet
		"10.212.8.0/30",                                                   // the ingress subnet
		"10.214.1.0/24",                                                   // the Docker pool
		"10.212.9.128/25",                                                 // the backup subnet
		"10.212.0.0/14",                                                   // contains them all
		"127.0.0.1/32", "169.254.0.0/16", "224.0.0.0/8", "224.0.0.251/32", // loopback, link-local, multicast
		"0.0.0.0/8", "0.0.0.0/32", "240.0.0.0/4", "255.255.255.255/32", // this network, reserved and broadcast
		"0.0.0.0/0",                                  // the open list is OpenAllowList's, never a validated one
		"203.0.113.1/24", "203.0.113.0/024", "x", "", // not canonical
	} {
		if p, err := ValidAllowList(c, []string{"192.0.2.0/24", s}); err == nil {
			t.Errorf("%q accepted: %v", s, p)
		}
	}
	if _, err := ValidAllowList(c, nil); err == nil {
		t.Error("empty list accepted")
	}
	long := make([]string, 33)
	for i := range long {
		long[i] = fmt.Sprintf("192.0.2.%d/32", i)
	}
	if _, err := ValidAllowList(c, long); err == nil {
		t.Error("33 prefixes accepted")
	}
	// Controls: public prefixes, and 32 of them.
	in := []string{"203.0.113.0/24", "198.51.100.7/32", "192.0.2.0/25"}
	got, err := ValidAllowList(c, in)
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	for i, p := range got {
		if p.String() != in[i] {
			t.Errorf("%d: %s", i, p)
		}
	}
	if _, err := ValidAllowList(c, long[:32]); err != nil {
		t.Errorf("32 prefixes: %v", err)
	}
	if o := OpenAllowList(); len(o) != 1 || o[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Errorf("OpenAllowList = %v", o)
	}
}

func TestConnString_CarriesNoPassword(t *testing.T) {
	const ref = "abcdefghij0123456789"
	if Zone("sp.test", "db") != "db.sp.test" || Host("sp.test", "db", ref) != ref+".db.sp.test" {
		t.Errorf("Zone/Host: %s %s", Zone("sp.test", "db"), Host("sp.test", "db", ref))
	}
	s := ConnString("sp.test", "db", ref, "postgres", TxnPort)
	if want := "postgresql://postgres." + ref + "@" + ref + ".db.sp.test:6543/postgres?sslmode=verify-full"; s != want {
		t.Fatalf("ConnString = %s, want %s", s, want)
	}
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, set := u.User.Password(); set || u.User.Username() != "postgres."+ref {
		t.Errorf("userinfo %v", u.User)
	}
}
