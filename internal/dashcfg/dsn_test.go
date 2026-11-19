package dashcfg

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

type dsnVectors struct {
	Pgcap      string `json:"pgcap"`
	MetaPortLo int    `json:"meta_port_lo"`
	MetaPortHi int    `json:"meta_port_hi"`
	Accepted   []struct {
		DSN         string `json:"dsn"`
		Login       string `json:"login"`
		SubnetIndex int    `json:"subnet_index"`
	} `json:"accepted"`
	Refused []struct{ Why, DSN string } `json:"refused"`
}

func loadVectors(t testing.TB) dsnVectors {
	b, err := os.ReadFile("testdata/dsn.json")
	if err != nil {
		t.Fatal(err)
	}
	var v dsnVectors
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDSN_Vectors(t *testing.T) {
	v := loadVectors(t)
	a, _ := For(defaultCfg())
	if v.Pgcap != a.Pgcap.String() || v.MetaPortLo != a.MetaPortLo || v.MetaPortHi != a.MetaPortHi {
		t.Fatalf("the vectors' addresses %+v are not the default node's %+v", v, a)
	}
	logins := map[string]bool{}
	for _, c := range v.Accepted {
		login, idx, err := ParseDSN(a, c.DSN)
		if err != nil || login != c.Login || idx != c.SubnetIndex {
			t.Errorf("%q: %q %d %v", c.DSN, login, idx, err)
		}
		logins[login] = true
	}
	if !logins[LoginRW] || !logins[LoginRO] {
		t.Error("the accepted vectors do not cover both logins")
	}
	for _, c := range v.Refused {
		if login, idx, err := ParseDSN(a, c.DSN); err == nil {
			t.Errorf("%s: %q accepted as %q %d", c.Why, c.DSN, login, idx)
		}
	}
	if len(v.Refused) < 10 {
		t.Error("too few refused vectors")
	}
	// Bounds: a string of the cap's length is read, one byte more is refused before any work.
	long := DSN(a, LoginRW, strings.Repeat("x", maxDSN-len(DSN(a, LoginRW, "", 0))), 0)
	if len(long) != maxDSN {
		t.Fatal(len(long))
	}
	if _, _, err := ParseDSN(a, long); err != nil {
		t.Errorf("a DSN of %d bytes: %v", maxDSN, err)
	}
	if _, _, err := ParseDSN(a, DSN(a, LoginRW, strings.Repeat("x", maxDSN+1-len(DSN(a, LoginRW, "", 0))), 0)); err == nil {
		t.Error("a DSN past the cap was accepted")
	}
	// Nothing parses against addresses Static left zero.
	if _, _, err := ParseDSN(Addrs{}, v.Accepted[0].DSN); err == nil {
		t.Error("accepted with a zero proxy address")
	}
	z := Static(wideCfg()) // the proxy's address, the port range zero
	if !z.Pgcap.IsValid() || z.MetaPortHi != 0 {
		t.Fatalf("%+v", z)
	}
	for _, s := range []string{DSN(z, LoginRW, "x", 0), DSN(z, LoginRW, "x", -MetaPortBase)} {
		if _, _, err := ParseDSN(z, s); err == nil {
			t.Errorf("%q accepted with a zero port range", s)
		}
	}
}

// Addresses with a meta port range but no proxy address (what Static gives a
// node whose gateway or allocation range takes the proxy's address) accept
// nothing: not even the string DSN renders from them.
func TestDSN_ZeroProxyAddressRefused(t *testing.T) {
	a, _ := For(defaultCfg())
	a.Pgcap = netip.Addr{}
	for _, s := range []string{DSN(a, LoginRW, "x", 0), DSN(a, LoginRO, "x", 1023)} {
		if login, idx, err := ParseDSN(a, s); err == nil {
			t.Errorf("%q accepted as %q %d", s, login, idx)
		}
	}
}

// FuzzParseDSN: no input panics, and whatever is accepted is exactly what DSN renders.
func FuzzParseDSN(f *testing.F) {
	v := loadVectors(f)
	for _, c := range v.Accepted {
		f.Add(c.DSN)
	}
	for _, c := range v.Refused {
		f.Add(c.DSN)
	}
	a, _ := For(defaultCfg())
	f.Fuzz(func(t *testing.T, s string) {
		login, idx, err := ParseDSN(a, s)
		if err != nil {
			return
		}
		pw := s[strings.IndexByte(s, ':')+3+len(login)+1 : strings.LastIndexByte(s, '@')]
		dec, ok := decodePassword(pw)
		if !ok || DSN(a, login, dec, idx) != s {
			t.Fatalf("accepted %q, which DSN does not render", s)
		}
	})
}
